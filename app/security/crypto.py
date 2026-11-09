"""Ed25519 asymmetric cryptography and cryptographic token utilities."""

import base64
import hashlib
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_ed25519_keypair() -> Tuple[str, str]:
    """Generates a new Ed25519 keypair and returns (private_pem, public_pem)."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return private_pem, public_pem


def sign_payload(private_key_pem: str, payload_bytes: bytes) -> str:
    """Signs payload bytes using Ed25519 private key, returning Base64 signature."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Provided key is not an Ed25519 private key")

    raw_signature = private_key.sign(payload_bytes)
    return base64.b64encode(raw_signature).decode("utf-8")


def verify_signature(public_key_pem: str, payload_bytes: bytes, signature_b64: str) -> bool:
    """Verifies an Ed25519 Base64 signature against payload bytes."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            return False
        raw_signature = base64.b64decode(signature_b64.encode("utf-8"))
        public_key.verify(raw_signature, payload_bytes)
        return True
    except (InvalidSignature, Exception):
        return False


def generate_secure_token(length_bytes: int = 32) -> str:
    """Generates a high-entropy URL-safe random string."""
    return secrets.token_urlsafe(length_bytes)


def hash_token(raw_token: str) -> str:
    """Computes SHA-256 hash of a session/validation token for secure lookup."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
