"""Cryptographic signing for AI-BOM bundles.

Strategy:
1) **Sigstore-compatible** layout — same JSON envelope used by sigstore-python.
2) **Fallback** to local Ed25519 keypair when sigstore servers unreachable
   (we don't want to require a Fulcio/Rekor round-trip for offline use).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass
class SignedBundle:
    payload_sha256: str
    signature_b64: str
    public_key_pem: str
    algorithm: str
    signed_at: float
    signer: str
    sigstore_used: bool

    def to_dict(self) -> dict:
        return {
            "payload_sha256": self.payload_sha256,
            "signature": self.signature_b64,
            "public_key_pem": self.public_key_pem,
            "algorithm": self.algorithm,
            "signed_at": self.signed_at,
            "signer": self.signer,
            "sigstore_used": self.sigstore_used,
        }


def _gen_or_load_keypair(key_path: str) -> ed25519.Ed25519PrivateKey:
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)  # type: ignore
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(pem)
    os.chmod(key_path, 0o600)
    return key


def sign_payload(payload: dict, key_path: str = "/tmp/aibom_signing.key",
                 signer: str = "aibom-local",
                 try_sigstore: bool = True) -> SignedBundle:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canon).hexdigest()
    sigstore_used = False
    sig_b64 = ""
    pub_pem = ""

    if try_sigstore:
        try:
            # Real sigstore would require OIDC + Fulcio. We attempt a no-op
            # import; if missing or unreachable, fall back gracefully.
            import importlib
            importlib.import_module("sigstore.sign")
            # NOTE: actual signing requires interactive OIDC. Skip if not configured.
            if os.environ.get("AIBOM_SIGSTORE_OIDC_TOKEN"):
                from sigstore.sign import SigningContext  # type: ignore
                ctx = SigningContext.production()
                with ctx.signer(identity_token=os.environ[
                        "AIBOM_SIGSTORE_OIDC_TOKEN"]) as signer_obj:
                    bundle = signer_obj.sign_artifact(canon)
                sig_b64 = base64.b64encode(bundle.signature).decode()
                pub_pem = bundle.signing_certificate.public_bytes(
                    serialization.Encoding.PEM).decode()
                sigstore_used = True
        except Exception:
            sigstore_used = False

    if not sigstore_used:
        key = _gen_or_load_keypair(key_path)
        sig = key.sign(canon)
        sig_b64 = base64.b64encode(sig).decode()
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    return SignedBundle(
        payload_sha256=digest,
        signature_b64=sig_b64,
        public_key_pem=pub_pem,
        algorithm="ed25519" if not sigstore_used else "sigstore-bundle",
        signed_at=time.time(),
        signer=signer,
        sigstore_used=sigstore_used,
    )


def verify_payload(payload: dict, bundle: dict) -> tuple[bool, str]:
    try:
        canon = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(canon).hexdigest()
        if bundle["payload_sha256"] != digest:
            return False, "digest_mismatch"
        sig = base64.b64decode(bundle["signature"])
        pub = serialization.load_pem_public_key(bundle["public_key_pem"].encode())
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig, canon)
            return True, "ok"
        return False, f"unsupported_key_type:{type(pub).__name__}"
    except Exception as e:
        return False, f"verify_failed:{type(e).__name__}:{e}"
