# Threat model & scope

## What this is
A generator and analyser for ML bills of materials: it turns a declared component
graph into a CycloneDX-ML SBOM and audits the *transitive* lineage for license and
provenance risk.

## Trust boundaries
- **The declared graph is the trust base.** The tool analyses what you declare; it
  cannot discover an ancestor nobody wrote down. This is why `undeclared-source`
  and `undeclared-license` are first-class findings — they mark exactly where the
  declaration is incomplete.
- **No network, no model execution.** It reads JSON and emits JSON, so it cannot be
  a pivot and cannot be compromised by the artifacts it describes. (For inspecting
  actual model files, see the companion `hf-supply-scanner`.)
- **Output is advice.** It never blocks a release itself; a CI policy acts on the
  exit code.

## Limits, stated plainly
- **Declaration-bound coverage.** A deliberately-omitted ancestor is undetectable
  here. Pair with artifact-level scanning and attestation (`container-trust`,
  `hf-supply-scanner`) for defence in depth.
- **The restrictive-license list is curated and incomplete.** It covers the common
  non-commercial/copyleft SPDX ids; an unusual bespoke license will not be flagged.
  Extending the set is a one-line change.
- **No legal conclusions.** It reports the license set in a lineage. Whether that
  combination is compatible with your intended use is a legal question, not a
  computed one — the tool deliberately does not claim compatibility verdicts.
- **Entity identity is by declared id.** Two records for the same upstream model
  under different ids will not be unified.

## Non-goals
- Determining license *compatibility* or giving legal advice.
- Discovering undeclared lineage.
- Scanning model file contents (that is `hf-supply-scanner`).

## Reporting
A lineage path the analyser fails to traverse, or a restrictive license it should
recognise, is a bug — report to **gabejar@usa.com**.
