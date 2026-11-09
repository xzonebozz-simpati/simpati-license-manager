"""Argon2id password hashing and verification module."""

import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

logger = logging.getLogger("simpati.security.hashing")

# Initialize Argon2id hasher with secure parameters
_hasher = PasswordHasher(
    time_cost=3,          # 3 iterations
    memory_cost=65536,    # 64 MiB memory
    parallelism=4,        # 4 threads
    hash_len=32,          # 32 bytes hash length
    salt_len=16           # 16 bytes random salt
)


def hash_password(plain_password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    if not plain_password:
        raise ValueError("Password cannot be empty")
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2id hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as exc:
        logger.error(f"Unexpected error during password verification: {exc}")
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Checks if the password hash needs to be re-hashed with updated parameters."""
    try:
        return _hasher.check_needs_rehash(hashed_password)
    except Exception:
        return True
