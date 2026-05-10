"""AI-BOM document builder.

Output formats:
- Native AI-BOM (JSON, our schema, comprehensive)
- CycloneDX 1.5+ML extension (industry standard SBOM tool compat)
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import platform
import sys
import uuid
from dataclasses import dataclass

from . import __version__ as TOOL_VERSION
from .scanner import ScanResult


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def build_native_aibom(scan: ScanResult, model_name: str,
                       model_version: str = "0.0.0",
                       extra: dict | None = None) -> dict:
    total_params = sum(w.parameter_count or 0 for w in scan.weights)
    bom = {
        "schemaVersion": "ai-bom/1.0",
        "id": f"ai-bom-{uuid.uuid4().hex[:12]}",
        "metadata": {
            "generated_at": _iso_now(),
            "tool": {"name": "aibom", "version": TOOL_VERSION},
            "host": {"python": sys.version.split()[0],
                     "platform": platform.platform()},
        },
        "model": {
            "name": model_name,
            "version": model_version,
            "root": scan.root,
            "total_size_bytes": scan.total_size_bytes,
            "scanned_files": scan.scanned_files,
            "license": scan.license,
            "readme_excerpt": scan.readme_excerpt,
            "estimated_parameters": total_params,
            "architectures": list({c.architecture for c in scan.configs
                                   if c.architecture}),
            "base_models": list({c.base_model for c in scan.configs
                                 if c.base_model}),
        },
        "components": {
            "weights": [w.to_dict() for w in scan.weights],
            "configs": [c.to_dict() for c in scan.configs],
            "datasets": [{"name": d, "type": "directory_or_file",
                          "path": d} for d in scan.datasets_present],
        },
        "security": {
            "pickle_high_risk_files": scan.pickle_high_risk_files,
            "pickle_findings": [
                {"path": w.relpath, "risk": w.pickle_risk,
                 "findings": w.pickle_findings}
                for w in scan.weights if w.pickle_findings
            ],
        },
    }
    if extra:
        bom["extensions"] = extra
    # Hash the canonical-ish bom (excluding signature placeholder) for integrity
    canon = json.dumps(bom, sort_keys=True, separators=(",", ":")).encode()
    bom["integrity"] = {
        "algorithm": "sha256",
        "hash": hashlib.sha256(canon).hexdigest(),
    }
    return bom


def build_cyclonedx_aibom(scan: ScanResult, model_name: str,
                          model_version: str = "0.0.0") -> dict:
    components = []
    for w in scan.weights:
        components.append({
            "type": "machine-learning-model",
            "bom-ref": f"weight:{w.sha256[:12]}",
            "name": w.relpath,
            "version": "1",
            "hashes": [{"alg": "SHA-256", "content": w.sha256}],
            "properties": [
                {"name": "size_bytes", "value": str(w.size_bytes)},
                {"name": "format", "value": w.format},
                {"name": "tensor_count", "value": str(w.tensor_count or 0)},
                {"name": "parameter_count", "value": str(w.parameter_count or 0)},
                {"name": "pickle_risk", "value": w.pickle_risk},
            ],
        })
    for c in scan.configs:
        components.append({
            "type": "data",
            "bom-ref": f"config:{c.sha256[:12]}",
            "name": c.relpath,
            "version": "1",
            "hashes": [{"alg": "SHA-256", "content": c.sha256}],
        })
    for d in scan.datasets_present:
        components.append({
            "type": "data",
            "bom-ref": f"dataset:{hashlib.sha1(d.encode()).hexdigest()[:12]}",
            "name": d,
            "version": "0",
            "description": "training/evaluation data referenced",
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _iso_now(),
            "tools": [{"vendor": "aibom", "name": "aibom", "version": TOOL_VERSION}],
            "component": {
                "type": "machine-learning-model",
                "bom-ref": f"model:{hashlib.sha1(model_name.encode()).hexdigest()[:12]}",
                "name": model_name,
                "version": model_version,
            },
        },
        "components": components,
    }


# ---------- diff (fine-tuning delta) ----------

def diff_boms(before: dict, after: dict) -> dict:
    """Compute weight/config delta between two AI-BOM documents (native schema)."""
    def _by_path(items: list[dict]) -> dict[str, dict]:
        return {it["path"]: it for it in items}
    bw = _by_path(before["components"]["weights"])
    aw = _by_path(after["components"]["weights"])
    bc = _by_path(before["components"]["configs"])
    ac = _by_path(after["components"]["configs"])
    added_w = [aw[p] for p in aw if p not in bw]
    removed_w = [bw[p] for p in bw if p not in aw]
    changed_w = [
        {"path": p, "before_sha256": bw[p]["sha256"],
         "after_sha256": aw[p]["sha256"],
         "size_delta": aw[p]["size_bytes"] - bw[p]["size_bytes"]}
        for p in aw if p in bw and bw[p]["sha256"] != aw[p]["sha256"]
    ]
    added_c = [ac[p] for p in ac if p not in bc]
    removed_c = [bc[p] for p in bc if p not in ac]
    changed_c = [
        {"path": p, "before_sha256": bc[p]["sha256"],
         "after_sha256": ac[p]["sha256"]}
        for p in ac if p in bc and bc[p]["sha256"] != ac[p]["sha256"]
    ]
    params_before = before["model"].get("estimated_parameters", 0)
    params_after = after["model"].get("estimated_parameters", 0)
    return {
        "schemaVersion": "ai-bom-diff/1.0",
        "before_id": before.get("id"),
        "after_id": after.get("id"),
        "weights": {
            "added": added_w, "removed": removed_w, "changed": changed_w,
        },
        "configs": {
            "added": added_c, "removed": removed_c, "changed": changed_c,
        },
        "parameter_delta": params_after - params_before,
        "size_delta_bytes": after["model"]["total_size_bytes"] -
                            before["model"]["total_size_bytes"],
        "is_fine_tune_candidate": (
            len(changed_w) > 0 and len(added_w) <= 2 and
            abs(params_after - params_before) < max(params_before, 1) * 0.05
        ),
    }
