#!/usr/bin/env python3
"""Bounded login input and PBKDF2 verification primitives."""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from dataclasses import dataclass


MAX_USERNAME_CHARS = 64
MAX_PASSWORD_CHARS = 1024
MAX_STORED_HASH_CHARS = 4096
MAX_PBKDF2_ITERATIONS = 5_000_000
MAX_SALT_BYTES = 128
MAX_DIGEST_BYTES = 128


class PasswordHashError(ValueError):
    """The stored hash cannot be safely processed by this panel version."""


@dataclass(frozen=True)
class PasswordHashSpec:
    iterations: int
    salt: bytes
    digest: bytes


def login_inputs_are_valid(username: str, password: str) -> bool:
    """Reject empty or unreasonably large credentials before DB/hash work."""

    if not isinstance(username, str) or not isinstance(password, str):
        return False
    username = username.strip()
    return bool(
        username
        and password
        and len(username) <= MAX_USERNAME_CHARS
        and len(password) <= MAX_PASSWORD_CHARS
    )


def parse_password_hash(stored: str) -> PasswordHashSpec:
    """Parse the supported PBKDF2 format without performing expensive hashing."""

    if not isinstance(stored, str) or not stored:
        raise PasswordHashError("password hash is empty")
    if len(stored) > MAX_STORED_HASH_CHARS:
        raise PasswordHashError("password hash is too long")

    try:
        kind, iterations_text, salt_b64, digest_b64 = stored.split("$", 3)
    except ValueError as exc:
        raise PasswordHashError("password hash field count is invalid") from exc

    if kind != "pbkdf2_sha256":
        raise PasswordHashError("password hash kind is unsupported")

    try:
        iterations = int(iterations_text, 10)
    except (TypeError, ValueError) as exc:
        raise PasswordHashError("PBKDF2 iteration count is invalid") from exc
    if iterations <= 0 or iterations > MAX_PBKDF2_ITERATIONS:
        raise PasswordHashError("PBKDF2 iteration count is outside safe bounds")

    try:
        salt = base64.b64decode(salt_b64, validate=True)
        digest = base64.b64decode(digest_b64, validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise PasswordHashError("password hash base64 is invalid") from exc

    if not (1 <= len(salt) <= MAX_SALT_BYTES):
        raise PasswordHashError("password hash salt length is outside safe bounds")
    if not (1 <= len(digest) <= MAX_DIGEST_BYTES):
        raise PasswordHashError("password hash digest length is outside safe bounds")

    return PasswordHashSpec(
        iterations=iterations,
        salt=salt,
        digest=digest,
    )


def verify_password(password: str, stored: str) -> bool:
    """Verify the panel PBKDF2 format with strict resource bounds."""

    if not isinstance(password, str):
        return False
    if not password or len(password) > MAX_PASSWORD_CHARS:
        return False

    try:
        spec = parse_password_hash(stored)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            spec.salt,
            spec.iterations,
            dklen=len(spec.digest),
        )
        return secrets.compare_digest(actual, spec.digest)
    except (PasswordHashError, ValueError, TypeError, UnicodeError):
        return False
