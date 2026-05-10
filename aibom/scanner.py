"""Walks a model directory, hashes weights, parses configs, extracts metadata.

Supports common formats: safetensors, .bin/.pt/.pth (pickle), .gguf, .onnx,
plus configs (config.json, tokenizer.json), READMEs, datasets/ folders.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


WEIGHT_EXTS = {".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".gguf", ".onnx", ".h5"}
PICKLE_EXTS = {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle"}
CONFIG_FILES = {"config.json", "tokenizer.json", "tokenizer_config.json",
                "generation_config.json", "preprocessor_config.json",
                "adapter_config.json", "training_args.bin"}


@dataclass
class WeightFile:
    path: str
    relpath: str
    size_bytes: int
    sha256: str
    format: str
    tensor_count: int | None = None
    parameter_count: int | None = None
    contains_pickle: bool = False
    pickle_risk: str = "none"   # none / low / medium / high
    pickle_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.relpath,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "format": self.format,
            "tensor_count": self.tensor_count,
            "parameter_count": self.parameter_count,
            "contains_pickle": self.contains_pickle,
            "pickle_risk": self.pickle_risk,
            "pickle_findings": self.pickle_findings,
        }


@dataclass
class ConfigFile:
    relpath: str
    sha256: str
    parsed: dict | None
    architecture: str | None = None
    base_model: str | None = None

    def to_dict(self) -> dict:
        return {"path": self.relpath, "sha256": self.sha256,
                "architecture": self.architecture,
                "base_model": self.base_model,
                "raw": self.parsed}


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ---------- safetensors ----------

def parse_safetensors(path: str) -> tuple[int | None, int | None]:
    """Return (tensor_count, total_params) by reading the header only."""
    try:
        with open(path, "rb") as f:
            hdr_len_bytes = f.read(8)
            if len(hdr_len_bytes) < 8:
                return None, None
            hdr_len = struct.unpack("<Q", hdr_len_bytes)[0]
            if hdr_len > 200_000_000:
                return None, None
            header = json.loads(f.read(hdr_len).decode("utf-8"))
        # __metadata__ is a side key, skip
        tensors = {k: v for k, v in header.items() if k != "__metadata__"}
        total_params = 0
        for t in tensors.values():
            shape = t.get("shape", [])
            n = 1
            for d in shape:
                n *= d
            total_params += n
        return len(tensors), total_params
    except Exception:
        return None, None


# ---------- pickle scanning ----------

DANGEROUS_OPCODES = [
    b"GLOBAL", b"REDUCE", b"BUILD",
    b"INST", b"OBJ", b"NEWOBJ", b"NEWOBJ_EX",
    b"STACK_GLOBAL",
]
SUSPICIOUS_MODULES = [
    "os", "subprocess", "posix", "nt", "shutil", "socket",
    "ctypes", "builtins", "__builtin__", "eval", "exec",
    "compile", "system", "popen", "fork", "spawn", "remove",
    "urllib", "requests", "httpx", "telnetlib", "ftplib",
    "pickle.loads", "marshal", "pty", "code", "codeop",
]


def scan_pickle_blob(data: bytes, max_scan: int = 5_000_000) -> tuple[str, list[str]]:
    """Heuristic pickle malware scan. Returns (risk, findings)."""
    findings: list[str] = []
    risk = "none"
    # Look at first N bytes for suspicious imports
    sample = data[:max_scan]
    text_view = sample.decode("latin-1", errors="ignore")
    for mod in SUSPICIOUS_MODULES:
        for m in re.finditer(re.escape(mod), text_view):
            ctx = text_view[max(0, m.start() - 5): m.end() + 30]
            if any(op in ctx for op in ("system", "popen", "fork", "exec", "spawn")):
                findings.append(f"dangerous_call:{mod}")
                risk = "high"
            elif risk != "high":
                findings.append(f"suspicious_module:{mod}")
                if risk == "none":
                    risk = "medium"
    # Reduce flag
    if b"\x80" in sample[:100] and b"R" in sample[:300]:  # protocol marker + REDUCE-ish
        if risk == "none":
            risk = "low"
    # Dedup & cap
    findings = list(dict.fromkeys(findings))[:20]
    return risk, findings


def scan_weight_file(path: str, root: str) -> WeightFile:
    relpath = os.path.relpath(path, root)
    size = os.path.getsize(path)
    fmt = Path(path).suffix.lstrip(".").lower()
    h = sha256_file(path)
    tcount = pcount = None
    contains_pickle = False
    risk = "none"
    findings: list[str] = []
    if fmt == "safetensors":
        tcount, pcount = parse_safetensors(path)
    if Path(path).suffix.lower() in PICKLE_EXTS:
        contains_pickle = True
        try:
            with open(path, "rb") as f:
                head = f.read(min(size, 2_000_000))
            risk, findings = scan_pickle_blob(head)
        except Exception:
            pass
    return WeightFile(
        path=path, relpath=relpath, size_bytes=size, sha256=h,
        format=fmt, tensor_count=tcount, parameter_count=pcount,
        contains_pickle=contains_pickle,
        pickle_risk=risk, pickle_findings=findings,
    )


# ---------- config parsing ----------

def scan_config_file(path: str, root: str) -> ConfigFile:
    relpath = os.path.relpath(path, root)
    h = sha256_file(path)
    parsed: dict | None = None
    arch = base = None
    if path.endswith(".json"):
        try:
            with open(path) as f:
                parsed = json.load(f)
        except Exception:
            parsed = None
    if parsed:
        if isinstance(parsed.get("architectures"), list) and parsed["architectures"]:
            arch = parsed["architectures"][0]
        elif isinstance(parsed.get("model_type"), str):
            arch = parsed["model_type"]
        base = parsed.get("_name_or_path") or parsed.get("base_model")
    return ConfigFile(relpath=relpath, sha256=h, parsed=parsed,
                      architecture=arch, base_model=base)


# ---------- license / dataset / lineage ----------

DATASET_HINTS = ["dataset", "corpus", "train", "eval", "data"]


@dataclass
class ScanResult:
    root: str
    weights: list[WeightFile]
    configs: list[ConfigFile]
    license: dict | None
    readme_excerpt: str | None
    datasets_present: list[str]
    total_size_bytes: int
    scanned_files: int
    pickle_high_risk_files: int

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "weights": [w.to_dict() for w in self.weights],
            "configs": [c.to_dict() for c in self.configs],
            "license": self.license,
            "readme_excerpt": self.readme_excerpt,
            "datasets_present": self.datasets_present,
            "total_size_bytes": self.total_size_bytes,
            "scanned_files": self.scanned_files,
            "pickle_high_risk_files": self.pickle_high_risk_files,
        }


def find_license(root: str) -> dict | None:
    for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "license", "COPYING"):
        p = os.path.join(root, name)
        if os.path.exists(p):
            try:
                with open(p, errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            ident = "unknown"
            tl = text.lower()
            for k in ("apache", "mit", "bsd", "gpl", "agpl", "lgpl",
                      "cc-by", "openrail", "llama 2", "llama 3"):
                if k in tl:
                    ident = k
                    break
            return {"file": name, "identifier_guess": ident, "size_bytes": len(text)}
    return None


def find_readme(root: str) -> str | None:
    for name in ("README.md", "README.rst", "README.txt", "README"):
        p = os.path.join(root, name)
        if os.path.exists(p):
            try:
                with open(p, errors="ignore") as f:
                    return f.read(4000)
            except Exception:
                pass
    return None


def find_datasets(root: str) -> list[str]:
    out = []
    for entry in os.listdir(root):
        full = os.path.join(root, entry)
        low = entry.lower()
        if os.path.isdir(full) and any(h in low for h in DATASET_HINTS):
            out.append(entry)
        elif low.endswith((".jsonl", ".csv", ".parquet", ".arrow")) and \
                any(h in low for h in DATASET_HINTS):
            out.append(entry)
    return out


def scan(root: str) -> ScanResult:
    root = os.path.abspath(root)
    weights: list[WeightFile] = []
    configs: list[ConfigFile] = []
    total = 0
    files = 0
    for dirpath, _dirs, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(p)
            except Exception:
                continue
            files += 1
            total += size
            ext = Path(fn).suffix.lower()
            if ext in WEIGHT_EXTS:
                weights.append(scan_weight_file(p, root))
            elif fn in CONFIG_FILES:
                configs.append(scan_config_file(p, root))
    return ScanResult(
        root=root,
        weights=weights,
        configs=configs,
        license=find_license(root),
        readme_excerpt=find_readme(root),
        datasets_present=find_datasets(root),
        total_size_bytes=total,
        scanned_files=files,
        pickle_high_risk_files=sum(1 for w in weights if w.pickle_risk == "high"),
    )
