from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:
        raise RuntimeError(
            "Proof-of-possession helpers require: pip install 'agenticdome-python-sdk[pop]'"
        ) from exc
    return hashes, serialization, padding, rsa


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _public_jwk(private_key) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    canonical = json.dumps(
        {key: jwk[key] for key in ("e", "kty", "n")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _b64u(hashlib.sha256(canonical).digest())


def generate_rsa_proof_key(*, key_size: int = 2048) -> dict[str, Any]:
    _, serialization, _, rsa = _crypto()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=max(2048, key_size))
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    jwk = _public_jwk(private_key)
    return {"private_key_pem": private_pem, "public_jwk": jwk, "thumbprint": jwk_thumbprint(jwk)}


def create_dpop_proof(
    private_key_pem: str,
    *,
    access_token: str,
    method: str,
    uri: str,
    proof_jti: str | None = None,
    issued_at: int | None = None,
) -> str:
    hashes, serialization, padding, _ = _crypto()
    private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    jwk = _public_jwk(private_key)
    header = {"typ": "dpop+jwt", "alg": "RS256", "jwk": jwk}
    payload = {
        "jti": proof_jti or uuid.uuid4().hex,
        "iat": int(issued_at or time.time()),
        "htm": str(method).upper(),
        "htu": str(uri),
        "ath": _b64u(hashlib.sha256(access_token.encode("utf-8")).digest()),
    }
    encoded_header = _b64u(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64u(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{encoded_header}.{encoded_payload}.{_b64u(signature)}"
