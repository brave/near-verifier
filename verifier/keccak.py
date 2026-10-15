# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Keccak-256 (Ethereum variant) and secp256k1 address derivation.

Original Keccak, not ``hashlib``'s SHA3-256 (different padding).
"""

from Cryptodome.Hash import keccak


def keccak256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of ``data`` (Ethereum variant)."""
    return bytes(keccak.new(digest_bits=256, data=data).digest())


def derive_ecdsa_address(public_key_hex: str) -> str | None:
    """Derive the lowercase 40-hex Ethereum-style address from a secp256k1 key.

    Accepts a 65-byte ``0x04``-prefixed or 64-byte raw ``x||y`` key; compressed
    keys return ``None``.
    """
    try:
        raw = bytes.fromhex(public_key_hex.removeprefix("0x"))
    except ValueError:
        return None
    if len(raw) == 65 and raw[0] == 0x04:
        raw = raw[1:]
    if len(raw) != 64:
        return None
    return keccak256(raw)[-20:].hex()
