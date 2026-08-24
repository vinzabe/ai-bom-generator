# ai-bom-generator

**A bill of materials for ML systems — with *transitive* provenance, because the risk is usually three hops up.**

A model is rarely standalone: it's a fine-tune of a merge of a base model trained on datasets of varying license and origin. "Is this safe to ship?" really means "what is its *full lineage*, and does any ancestor carry a restrictive license or an undeclared origin?" A flat dependency list cannot answer that. A provenance DAG can.

```
$ aibom audit graph.json
ship  licenses: Apache-2.0, CC-BY-4.0, CC-BY-NC-4.0
  ⚠ restrictive-license: research-corpus is CC-BY-NC-4.0 (1 hop(s) up)
  ⚠ undeclared-source: leaked-weights has no declared source (3 hop(s) up)
  ⚠ undeclared-license: leaked-weights has no declared license (3 hop(s) up)
```

The shippable model is nominally Apache-2.0. Following the DAG reveals a **non-commercial dataset one hop up** and **weights with no declared origin three hops up** — exactly the lineage risk a flat SBOM misses.

## What it does

- **Transitive lineage analysis** — BFS over derivation edges with hop distance, so you know *how far up* a problem is. Cycle-safe.
- **License propagation** — the `effective_licenses` of an artifact is the union across its whole lineage: the set it must actually comply with, not just its own declared license.
- **Risk flagging** — restrictive licenses (`CC-BY-NC-*`, `AGPL`, `research-only`, …), undeclared sources, and undeclared licenses, each attributed to the specific ancestor.
- **CycloneDX-ML output** — a standard SBOM (spec 1.5) using the ML component types `machine-learning-model` and `data`, with provenance emitted as `dependencies`.

## Quickstart (60 seconds)

```bash
git clone https://github.com/vinzabe/ai-bom-generator && cd ai-bom-generator
python -m pip install -e ".[dev]"

aibom generate graph.json           # emit a CycloneDX-ML SBOM
aibom audit graph.json              # audit every shippable root's lineage
aibom audit graph.json --json       # machine-readable
aibom audit graph.json --component base-llm
```

`audit` exit codes: `0` clean, `2` lineage findings present, `1` error — so CI blocks a release whose lineage acquired a restrictive license.

## The component graph

```json
{"components": [
  {"id":"leak","name":"leaked-weights","type":"machine-learning-model","license":"","source":""},
  {"id":"base","name":"base-llm","type":"machine-learning-model",
   "license":"Apache-2.0","source":"https://hf.co/org/base","derived_from":["leak"]},
  {"id":"ship","name":"product-model","type":"machine-learning-model",
   "license":"Apache-2.0","source":"https://hf.co/org/ship","derived_from":["base","nc-data"]}
]}
```

`roots()` identifies the components nothing else derives from — your shippable artifacts — so `audit` with no arguments checks exactly what you'd release.

## Development

```bash
python -m pip install -e ".[dev]"
pytest --cov=aibom       # 19 tests, ~94% coverage
mypy --strict src/aibom  # clean
ruff check src tests     # clean
```

## License

MIT © vinzabe
