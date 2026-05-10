"""CLI: `aibom scan / generate / sign / verify / diff`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bom import build_cyclonedx_aibom, build_native_aibom, diff_boms
from .scanner import scan
from .signing import sign_payload, verify_payload


def cmd_scan(args: argparse.Namespace) -> int:
    res = scan(args.path)
    out = json.dumps(res.to_dict(), indent=2, default=str)
    if args.output:
        Path(args.output).write_text(out)
        print(f"wrote {args.output}")
    else:
        print(out)
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    res = scan(args.path)
    if args.format == "native":
        bom = build_native_aibom(res, model_name=args.name,
                                 model_version=args.version)
    else:
        bom = build_cyclonedx_aibom(res, model_name=args.name,
                                    model_version=args.version)
    text = json.dumps(bom, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.output} ({len(text)} bytes)")
    else:
        print(text)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.bom).read_text())
    bundle = sign_payload(payload, key_path=args.key,
                          signer=args.signer)
    out = json.dumps(bundle.to_dict(), indent=2)
    Path(args.output).write_text(out)
    print(f"signed -> {args.output} (sigstore_used={bundle.sigstore_used})")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.bom).read_text())
    bundle = json.loads(Path(args.bundle).read_text())
    ok, reason = verify_payload(payload, bundle)
    print(f"verify: {'OK' if ok else 'FAIL'} ({reason})")
    return 0 if ok else 2


def cmd_diff(args: argparse.Namespace) -> int:
    a = json.loads(Path(args.before).read_text())
    b = json.loads(Path(args.after).read_text())
    d = diff_boms(a, b)
    out = json.dumps(d, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(out)
        print(f"wrote {args.output}")
    else:
        print(out)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aibom",
                                description="AI Bill-of-Materials generator")
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("scan", help="Walk a model directory and dump scan JSON")
    s.add_argument("path"); s.add_argument("--output", "-o")
    s.set_defaults(func=cmd_scan)

    g = sp.add_parser("generate", help="Generate AI-BOM (native or cyclonedx)")
    g.add_argument("path"); g.add_argument("--output", "-o", required=True)
    g.add_argument("--name", required=True)
    g.add_argument("--version", default="0.0.0")
    g.add_argument("--format", choices=["native", "cyclonedx"], default="native")
    g.set_defaults(func=cmd_generate)

    sn = sp.add_parser("sign", help="Sign an AI-BOM JSON file")
    sn.add_argument("bom"); sn.add_argument("--output", "-o", required=True)
    sn.add_argument("--key", default="/tmp/aibom_signing.key")
    sn.add_argument("--signer", default="aibom-local")
    sn.set_defaults(func=cmd_sign)

    v = sp.add_parser("verify", help="Verify a signed AI-BOM bundle")
    v.add_argument("bom"); v.add_argument("bundle")
    v.set_defaults(func=cmd_verify)

    d = sp.add_parser("diff", help="Diff two AI-BOM JSON files (fine-tune delta)")
    d.add_argument("before"); d.add_argument("after")
    d.add_argument("--output", "-o")
    d.set_defaults(func=cmd_diff)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
