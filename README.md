# AI-BOM Generator

Software-Bill-of-Materials, but for ML systems. Produces signed,
machine-readable bundles describing every artifact in a model release:
weights, configs, tokenizer, datasets, license, parent base model, and
fine-tuning deltas.

## Features
- Hashes weights (sha256), parses `safetensors` headers (tensor count + parameter count)
- Detects suspicious **pickle** opcodes / dangerous module references in `.bin/.pt/.pth/.ckpt`
- Captures license, README excerpt, dataset directory references
- Outputs **native AI-BOM JSON** *or* **CycloneDX 1.5 + ML extension**
- **Cryptographic signing** (Ed25519, sigstore-compatible envelope; tries real sigstore if `AIBOM_SIGSTORE_OIDC_TOKEN` set)
- **Fine-tuning diff** between two BOMs — flags fine-tune candidates

## Install

```bash
git clone https://github.com/vinzabe/ai-bom-generator.git
cd ai-bom-generator
pip install -r requirements.txt
```

## CLI

```bash
# Scan a model dir
python -m aibom.cli scan /path/to/model

# Generate an AI-BOM
python -m aibom.cli generate /path/to/model --name myllm --version 1.0 -o bom.json

# CycloneDX flavor (industry SBOM tool compat)
python -m aibom.cli generate /path/to/model --name myllm --format cyclonedx -o bom.cdx.json

# Sign + verify
python -m aibom.cli sign bom.json -o bom.sig.json
python -m aibom.cli verify bom.json bom.sig.json

# Diff two BOMs (e.g. before/after fine-tune)
python -m aibom.cli diff base.bom.json finetuned.bom.json -o delta.json
```

## Test

```bash
python tests/test_aibom.py
```

## Why pickle-scanning?
Loading a malicious `.pt`/`.bin` file via `torch.load` is **arbitrary code
execution**. AI-BOM flags any pickle that references `os`, `subprocess`,
`socket`, `ctypes`, `__reduce__`-with-system, etc., letting you fail CI
before the weights ever touch a GPU box.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability disclosure policy.

## License

MIT — see [LICENSE](./LICENSE).
