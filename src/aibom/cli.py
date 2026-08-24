"""CLI: generate a CycloneDX-ML SBOM, or audit lineage risk.

`audit` exit codes: 0 clean, 2 lineage findings present, 1 error.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__
from .cyclonedx import to_json
from .loader import load_graph
from .provenance import analyze, effective_licenses

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 2


def cmd_generate(a: argparse.Namespace) -> int:
    print(to_json(load_graph(a.graph)))
    return EXIT_OK


def cmd_audit(a: argparse.Namespace) -> int:
    graph = load_graph(a.graph)
    targets = graph.roots() if not a.component else [
        c for c in graph.components if c.id == a.component]
    all_findings = []
    payload: list[dict[str, Any]] = []
    for c in targets:
        findings = analyze(graph, c.id)
        licenses = sorted(effective_licenses(graph, c.id))
        all_findings.extend(findings)
        payload.append({"component": c.id, "effective_licenses": licenses,
                        "findings": [{"kind": f.kind, "ancestor": f.ancestor_id,
                                      "hops": f.hops, "detail": f.detail}
                                     for f in findings]})
    if a.json:
        print(json.dumps(payload, indent=2))
    else:
        for item in payload:
            print(f"{item['component']}  "
                  f"licenses: {', '.join(item['effective_licenses']) or 'none'}")
            for f in item["findings"]:
                print(f"  ⚠ {f['kind']}: {f['detail']}")
            if not item["findings"]:
                print("  ✓ no lineage risks")
    return EXIT_FINDINGS if all_findings else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aibom", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="emit a CycloneDX-ML SBOM")
    g.add_argument("graph")
    g.set_defaults(func=cmd_generate)

    a = sub.add_parser("audit", help="audit transitive lineage for risks")
    a.add_argument("graph")
    a.add_argument("--component", help="audit one component (default: all roots)")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
