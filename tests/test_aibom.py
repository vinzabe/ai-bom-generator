"""End-to-end smoke tests for AI-BOM."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile


# --- standalone-repo shim: add project root to sys.path ---
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_PROJECT_ROOT = _os.path.normpath(_os.path.join(_HERE, '..'))

sys.path.insert(0, _PROJECT_ROOT)

from aibom.bom import build_cyclonedx_aibom, build_native_aibom, diff_boms
from aibom.scanner import scan, scan_pickle_blob
from aibom.signing import sign_payload, verify_payload
from tests.fixture_builder import (
    build_clean_model,
    build_finetuned_model,
    build_malicious_model,
)

WORKDIR = tempfile.mkdtemp(prefix="aibom_test_")


def test_scan_clean_model():
    root = build_clean_model(os.path.join(WORKDIR, "clean"))
    res = scan(root)
    assert res.scanned_files >= 5
    assert len(res.weights) == 1
    w = res.weights[0]
    assert w.format == "safetensors"
    assert w.tensor_count == 3
    assert w.parameter_count == 128 * 64 + 64 + 1000 * 128
    assert res.license and "apache" in res.license["identifier_guess"]
    assert any(c.architecture == "LlamaForCausalLM" for c in res.configs)
    assert "training_data" in res.datasets_present
    print(f"  [PASS] params={w.parameter_count}, license={res.license['identifier_guess']}")


def test_scan_malicious_pickle():
    root = build_malicious_model(os.path.join(WORKDIR, "evil"))
    res = scan(root)
    bad = [w for w in res.weights if w.contains_pickle]
    assert bad and bad[0].pickle_risk in ("medium", "high")
    assert any("os" in f or "system" in f for f in bad[0].pickle_findings)
    print(f"  [PASS] malicious pickle: risk={bad[0].pickle_risk} findings={bad[0].pickle_findings}")


def test_pickle_scanner_low_risk():
    # Truly empty data
    risk, findings = scan_pickle_blob(b"\x80\x04N.")
    assert risk in ("none", "low")
    print(f"  [PASS] empty pickle low risk={risk}")


def test_native_bom_generation():
    root = build_clean_model(os.path.join(WORKDIR, "for_bom"))
    res = scan(root)
    bom = build_native_aibom(res, model_name="testmodel", model_version="1.0.0")
    assert bom["schemaVersion"] == "ai-bom/1.0"
    assert bom["model"]["name"] == "testmodel"
    assert bom["integrity"]["algorithm"] == "sha256"
    assert len(bom["components"]["weights"]) == 1
    assert bom["model"]["estimated_parameters"] > 0
    print(f"  [PASS] native bom: {bom['model']['estimated_parameters']} params, "
          f"hash={bom['integrity']['hash'][:12]}")


def test_cyclonedx_bom_generation():
    root = build_clean_model(os.path.join(WORKDIR, "for_cdx"))
    res = scan(root)
    bom = build_cyclonedx_aibom(res, model_name="cdx-model", model_version="2.0")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert any(c["type"] == "machine-learning-model" for c in bom["components"])
    print(f"  [PASS] cyclonedx components={len(bom['components'])}")


def test_signing_and_verification():
    root = build_clean_model(os.path.join(WORKDIR, "for_sign"))
    res = scan(root)
    bom = build_native_aibom(res, model_name="sigmodel")
    bundle = sign_payload(bom, key_path=os.path.join(WORKDIR, "test.key"))
    assert bundle.signature_b64
    ok, reason = verify_payload(bom, bundle.to_dict())
    assert ok, reason
    # Tamper -> verify fails
    tampered = dict(bom)
    tampered["model"] = dict(tampered["model"], name="HACKED")
    ok2, _ = verify_payload(tampered, bundle.to_dict())
    assert not ok2
    print(f"  [PASS] sign+verify (tamper detected). algo={bundle.algorithm}")


def test_diff_finetuning_detection():
    root_a = build_clean_model(os.path.join(WORKDIR, "before"))
    res_a = scan(root_a)
    bom_a = build_native_aibom(res_a, model_name="basemodel")

    root_b = build_finetuned_model(root_a, os.path.join(WORKDIR, "after"))
    res_b = scan(root_b)
    bom_b = build_native_aibom(res_b, model_name="basemodel-ft")

    d = diff_boms(bom_a, bom_b)
    assert len(d["weights"]["changed"]) == 1
    assert d["is_fine_tune_candidate"] is True
    print(f"  [PASS] diff: changed={len(d['weights']['changed'])} "
          f"fine_tune={d['is_fine_tune_candidate']}")


def test_cli_end_to_end():
    root = build_clean_model(os.path.join(WORKDIR, "cli_model"))
    bom_out = os.path.join(WORKDIR, "cli.bom.json")
    sig_out = os.path.join(WORKDIR, "cli.sig.json")
    cdx_out = os.path.join(WORKDIR, "cli.cdx.json")

    env = dict(os.environ)
    cmd_base = [sys.executable, "-m", "aibom.cli"]
    # generate native
    r = subprocess.run(cmd_base + ["generate", root, "--name", "clitest",
                                    "--version", "1.2.3", "--format", "native",
                                    "-o", bom_out],
                       env=env, cwd=_PROJECT_ROOT,
                       capture_output=True, text=True, check=True)
    assert os.path.exists(bom_out)
    # generate cyclonedx
    subprocess.run(cmd_base + ["generate", root, "--name", "clitest",
                                "--format", "cyclonedx", "-o", cdx_out],
                   env=env, cwd=_PROJECT_ROOT, check=True)
    cdx = json.loads(open(cdx_out).read())
    assert cdx["bomFormat"] == "CycloneDX"
    # sign
    subprocess.run(cmd_base + ["sign", bom_out, "-o", sig_out,
                                "--key", os.path.join(WORKDIR, "cli.key")],
                   env=env, cwd=_PROJECT_ROOT, check=True)
    # verify
    r = subprocess.run(cmd_base + ["verify", bom_out, sig_out],
                       env=env, cwd=_PROJECT_ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0 and "OK" in r.stdout
    print(f"  [PASS] CLI: generate -> sign -> verify OK")

    # CLI diff
    bom_a = bom_out
    ftroot = build_finetuned_model(root, os.path.join(WORKDIR, "cli_after"))
    bom_b = os.path.join(WORKDIR, "cli_after.bom.json")
    subprocess.run(cmd_base + ["generate", ftroot, "--name", "clitest-ft",
                                "-o", bom_b],
                   env=env, cwd=_PROJECT_ROOT, check=True)
    diff_out = os.path.join(WORKDIR, "diff.json")
    subprocess.run(cmd_base + ["diff", bom_a, bom_b, "-o", diff_out],
                   env=env, cwd=_PROJECT_ROOT, check=True)
    d = json.loads(open(diff_out).read())
    assert d["weights"]["changed"]
    print(f"  [PASS] CLI diff: {len(d['weights']['changed'])} changed weights")


def main() -> int:
    tests = [
        test_scan_clean_model,
        test_scan_malicious_pickle,
        test_pickle_scanner_low_risk,
        test_native_bom_generation,
        test_cyclonedx_bom_generation,
        test_signing_and_verification,
        test_diff_finetuning_detection,
        test_cli_end_to_end,
    ]
    p = f = 0
    for t in tests:
        print(f"\n>>> {t.__name__}")
        try:
            t(); p += 1
        except Exception as e:
            print(f"  [FAIL] {e}")
            import traceback; traceback.print_exc()
            f += 1
    shutil.rmtree(WORKDIR, ignore_errors=True)
    print(f"\n{'='*60}\nAI-BOM: {p} passed, {f} failed")
    return 0 if f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
