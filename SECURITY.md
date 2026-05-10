# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **AI-BOM Generator**, please
report it privately. Do **not** open a public GitHub issue.

**Email:** security@vinzabe.dev (or open a GitHub Security Advisory)

Please include:
- A clear description of the issue
- Steps to reproduce (PoC preferred)
- The version / commit SHA you tested against
- Any suggested mitigation

We aim to acknowledge new reports within **72 hours** and to publish a
fix or mitigation within **30 days** for high-severity issues.

## Scope

In scope:
- Pickle scanner false negatives (malicious pickle that the scanner
  marks as clean) — **highest priority**
- Signature forgery / verification bypass
- BOM tampering not detected by `verify`
- Sigstore envelope handling bugs
- Path traversal in `scan` / `generate`
- CycloneDX output that fails official validators

Out of scope:
- The scanner does not (and cannot) detect malicious behaviors that
  require **runtime** loading of weights — it is a static, lightweight
  triage tool. For full safety, also use `picklescan`, `safetensors`
  format conversion, and sandboxed loading.
- The scanner intentionally errs on the side of false positives for
  pickle files referencing `os`, `subprocess`, etc.

## Critical safety warning

**Never `torch.load()` a pickle file flagged as suspicious without a
sandbox.** A flagged pickle is, by definition, capable of arbitrary
code execution the moment it is deserialized. AI-BOM is a **pre-load
gate**, not a sandbox.

Recommended workflow:
1. `aibom scan model_dir/` → if any pickle finding, **stop**
2. Convert to `safetensors` in a disposable container
3. Re-scan: `aibom scan model_dir/` (should now be clean)
4. `aibom generate ... && aibom sign ...`
5. Distribute the signed BOM with the model

## Threat model

We assume:
- The user trusts the host running `aibom`
- The user does **not** trust the model artifacts being scanned
- Adversaries may craft pickle files that:
  - Use obfuscated imports (`__import__('o'+'s')`)
  - Hide payload in `__reduce_ex__` chains
  - Embed payload in nested pickles
- The scanner does best-effort opcode walking; sophisticated obfuscation
  may evade detection. Always combine with safetensors conversion.

## Hardening checklist for production deployments

- [ ] Run `aibom scan` in a sandbox (gVisor, Firecracker, or unprivileged
      container) — even *parsing* a malicious file should be isolated
- [ ] Pin sigstore CA roots (`AIBOM_SIGSTORE_TRUST_ROOT`)
- [ ] Store signing keys in HSM / KMS, not on disk
- [ ] Verify BOMs in CI before any model is deployed
- [ ] Reject any pickle file at the artifact-store boundary (require
      safetensors or GGUF)
- [ ] Treat `--format cyclonedx` BOMs as input to your existing SBOM
      tooling (Dependency-Track, etc.)

## Supply chain

- All Python deps are pinned via `requirements.txt`
- Cryptography uses `cryptography` (Ed25519) + optional `sigstore`
- BOMs validate against CycloneDX 1.5 JSON schema
