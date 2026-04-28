# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Digest normalization helpers for provenance generation."""

import base64
import binascii
import re

HASH_SIZE_BYTES = {
    "blake3": 32,
    "md5": 16,
    "sha1": 20,
    "sha256": 32,
    "sha512": 64,
}
NIX32_ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"
NIX32_INDEX = {char: index for index, char in enumerate(NIX32_ALPHABET)}


def canonical_hash_algo(hash_algo):
    """Normalize legacy hash algorithm labels to plain algorithm names."""
    if not hash_algo:
        return None
    return str(hash_algo).removeprefix("r:")


def hash_size_bytes(hash_algo):
    """Return expected digest size for the given algorithm."""
    hash_algo = canonical_hash_algo(hash_algo)
    if hash_algo is None:
        return None
    return HASH_SIZE_BYTES.get(hash_algo)


def decode_nix32(hash_value, size_bytes):
    """Decode nix base32 digest strings into raw bytes."""
    try:
        value = 0
        for char in hash_value:
            value = value * 32 + NIX32_INDEX[char]
    except KeyError:
        return None

    if value.bit_length() > size_bytes * 8:
        return None

    encoded_size = (len(hash_value) * 5 + 7) // 8
    raw = value.to_bytes(encoded_size, "little")
    return raw[:size_bytes].ljust(size_bytes, b"\0")


def decode_hash_bytes(hash_value, hash_algo):
    """Decode known Nix hash encodings into raw bytes."""
    size_bytes = hash_size_bytes(hash_algo)
    if size_bytes is None:
        return None

    if re.fullmatch(rf"[0-9a-f]{{{size_bytes * 2}}}", hash_value):
        return bytes.fromhex(hash_value)

    if len(hash_value) == (size_bytes * 8 + 4) // 5:
        decoded = decode_nix32(hash_value, size_bytes)
        if decoded is not None:
            return decoded

    padding = "=" * (-len(hash_value) % 4)
    try:
        decoded = base64.b64decode(hash_value + padding, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(decoded) != size_bytes:
        return None
    return decoded


def split_hash_value(hash_value, hash_algo=None):
    """Split a typed hash string into canonical algorithm and raw value."""
    hash_algo = canonical_hash_algo(hash_algo)
    hash_value = str(hash_value).strip()

    if hash_algo:
        for separator in (":", "-"):
            legacy_prefix = f"r:{hash_algo}{separator}"
            if hash_value.startswith(legacy_prefix):
                return hash_algo, hash_value.removeprefix(legacy_prefix)
            prefix = f"{hash_algo}{separator}"
            if hash_value.startswith(prefix):
                return hash_algo, hash_value.removeprefix(prefix)

    match = re.match(
        r"^(?P<algo>(?:r:)?[A-Za-z0-9]+)(?P<sep>[:-])(?P<rest>.+)$",
        hash_value,
    )
    if match:
        return canonical_hash_algo(match.group("algo")), match.group("rest")

    return hash_algo, hash_value


def normalize_digest(hash_value, hash_algo=None):
    """Return digest in a canonical base16 representation."""
    if not hash_value:
        return None
    hash_value = str(hash_value).strip()
    if not hash_value:
        return None

    hash_algo, raw_hash_value = split_hash_value(hash_value, hash_algo=hash_algo)
    if not hash_algo:
        return None

    decoded = decode_hash_bytes(raw_hash_value, hash_algo)
    if decoded is None:
        return None
    return {hash_algo: decoded.hex()}


def output_digest(data, *, normalize_digest_fn=normalize_digest):
    """Return digest from derivation output metadata when available."""
    if not isinstance(data, dict):
        return None
    hash_value = data.get("hash")
    if not hash_value:
        return None
    return normalize_digest_fn(hash_value, hash_algo=data.get("hashAlgo"))
