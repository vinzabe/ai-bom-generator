"""Build a synthetic model directory for testing."""
from __future__ import annotations

import json
import os
import pickle
import struct
from pathlib import Path


def make_safetensors(path: str, shapes: dict[str, list[int]]) -> None:
    """Write a tiny but valid safetensors file."""
    header: dict = {}
    offset = 0
    for name, shape in shapes.items():
        n = 1
        for d in shape:
            n *= d
        size = n * 4  # f32
        header[name] = {"dtype": "F32", "shape": shape,
                        "data_offsets": [offset, offset + size]}
        offset += size
    header_bytes = json.dumps(header).encode()
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        # zero data
        f.write(b"\x00" * offset)


def make_config(path: str, model_type: str = "llama",
                arch: str = "LlamaForCausalLM",
                base: str | None = "meta-llama/Llama-3-8B") -> None:
    cfg = {
        "model_type": model_type,
        "architectures": [arch],
        "vocab_size": 32000,
        "hidden_size": 1024,
        "num_hidden_layers": 4,
        "num_attention_heads": 8,
    }
    if base:
        cfg["_name_or_path"] = base
    Path(path).write_text(json.dumps(cfg, indent=2))


def make_safe_pickle(path: str) -> None:
    """A 'clean' pickle: no dangerous opcodes."""
    with open(path, "wb") as f:
        pickle.dump({"weights_meta": "stub", "version": 1}, f)


def make_malicious_pickle(path: str) -> None:
    """A pickle that references os.system — should trigger HIGH risk."""
    class _Evil:
        def __reduce__(self):
            import os as _os
            return (_os.system, ("echo PWNED",))
    with open(path, "wb") as f:
        pickle.dump(_Evil(), f)


def build_clean_model(root: str, name: str = "tinybert") -> str:
    os.makedirs(root, exist_ok=True)
    make_safetensors(os.path.join(root, "model.safetensors"),
                     {"layer.0.weight": [128, 64],
                      "layer.0.bias": [64],
                      "embedding.weight": [1000, 128]})
    make_config(os.path.join(root, "config.json"))
    Path(os.path.join(root, "tokenizer.json")).write_text(
        json.dumps({"version": "1.0", "model": {"type": "BPE"}}))
    Path(os.path.join(root, "README.md")).write_text(
        f"# {name}\n\nA tiny model for testing.\n")
    Path(os.path.join(root, "LICENSE")).write_text(
        "Apache License 2.0\n\nLicensed under Apache.")
    os.makedirs(os.path.join(root, "training_data"), exist_ok=True)
    Path(os.path.join(root, "training_data", "train.jsonl")).write_text(
        '{"text":"hello"}\n')
    return root


def build_finetuned_model(src_root: str, dst_root: str) -> str:
    """Copy clean -> dst, mutate one weight to look like a fine-tune delta."""
    import shutil
    if os.path.exists(dst_root):
        shutil.rmtree(dst_root)
    shutil.copytree(src_root, dst_root)
    # Change a single byte in safetensors data section to alter sha256
    p = os.path.join(dst_root, "model.safetensors")
    with open(p, "r+b") as f:
        f.seek(-1, os.SEEK_END)
        f.write(b"\x01")
    return dst_root


def build_malicious_model(root: str) -> str:
    os.makedirs(root, exist_ok=True)
    make_safetensors(os.path.join(root, "model.safetensors"),
                     {"w": [10, 10]})
    make_config(os.path.join(root, "config.json"))
    make_malicious_pickle(os.path.join(root, "evil_weights.pt"))
    return root
