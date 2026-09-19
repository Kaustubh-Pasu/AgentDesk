"""Argon2id password hashing (argon2-cffi). Never hand-rolled."""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher(type=Type.ID)  # library defaults (RFC 9106 low-memory profile)

# A real hash of a random value: verifying against it for unknown users keeps timing uniform.
_DUMMY_HASH = _hasher.hash("agentdesk-dummy-password-for-constant-time-path")

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256


class WeakPasswordError(ValueError):
    pass


def check_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise WeakPasswordError("password too long")
    if len(set(password)) < 5:
        raise WeakPasswordError("password is too repetitive")


def hash_password(password: str) -> str:
    check_password_strength(password)
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-shape verification: unknown users still pay for one Argon2 verification."""
    if len(password) > MAX_PASSWORD_LENGTH:
        password = password[:MAX_PASSWORD_LENGTH]
    target = password_hash or _DUMMY_HASH
    try:
        ok = _hasher.verify(target, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return bool(ok and password_hash)


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
