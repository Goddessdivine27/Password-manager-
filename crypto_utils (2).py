"""
Crypto primitives for the vault.

Design:
- Login auth uses Argon2id password hashing (argon2-cffi), salt is internal
  to the hash string, never stored separately.
- The vault encryption key is a SEPARATE Argon2id derivation from the same
  master password, using its own random salt (enc_salt, stored per user).
  This key only ever lives in server memory for the duration of a session
  and is never written to disk or sent to the browser.
- Each entry is encrypted with AES-256-GCM using a fresh random 12-byte
  nonce per encryption call. The nonce is stored alongside the ciphertext
  (nonce || ciphertext) and is never reused across encryptions.
"""

import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Argon2id cost parameters. Tuned for a small single-user app; raise
# memory_cost/time_cost if you want stronger (slower) hashing.
_TIME_COST = 3
_MEMORY_COST = 65536  # 64 MiB
_PARALLELISM = 4
_KEY_LEN = 32  # AES-256

_ph = PasswordHasher(
    time_cost=_TIME_COST,
    memory_cost=_MEMORY_COST,
    parallelism=_PARALLELISM,
    hash_len=_KEY_LEN,
)


def new_salt(n: int = 16) -> bytes:
    return os.urandom(n)


def hash_password(password: str) -> str:
    """Argon2id hash for login verification. Salt is embedded in the output string."""
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def derive_key(password: str, salt: bytes) -> bytearray:
    """
    Derive a 32-byte AES-256 key from the master password + per-user salt.

    Returned as a mutable bytearray (not bytes) so the caller can wipe()
    it when the session ends, instead of leaving it for the garbage
    collector. Note this only protects OUR long-lived copy: the
    intermediate bytes object argon2-cffi's C extension produces
    internally is outside our control, same as any plaintext password
    string Python creates along the way. Application code cannot fully
    solve memory-exposure problems like swap or string immutability;
    see README "Known limitations".
    """
    raw = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=_TIME_COST,
        memory_cost=_MEMORY_COST,
        parallelism=_PARALLELISM,
        hash_len=_KEY_LEN,
        type=Type.ID,
    )
    return bytearray(raw)


def wipe(buf: bytearray) -> None:
    """Zero a mutable buffer in place. Best-effort: reduces the window a key
    sits in memory, but cannot guarantee earlier copies (e.g. swapped pages,
    upstream C-extension buffers) are also cleared."""
    for i in range(len(buf)):
        buf[i] = 0


def encrypt(key: bytearray, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce(12) || ciphertext_with_tag."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)  # accepts bytearray directly, no extra copy needed
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt(key: bytearray, blob: bytes) -> bytes:
    """Inverse of encrypt(). Raises cryptography.exceptions.InvalidTag on tamper/wrong key."""
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)
