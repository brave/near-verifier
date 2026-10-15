# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for verifier.keccak (Keccak-256 + secp256k1 address derivation)."""

from verifier.keccak import derive_ecdsa_address, keccak256
from verifier.main import _signing_key_binds_address

_REAL_PUBKEY = (
    "a31cdd4f9443ebc31cffffd688621a1807b41c2f02649881d010f881de0a5e94"
    "ddec8208161e8fa02ae3748700bf8be3333c9683d6e13e0bbe7e92ee7d2243b8"
)
_REAL_ADDRESS = "0x56d070df1c6be444b007839ef9cf67cec7c12b8b"


class TestKeccak256:
    def test_empty_vector(self) -> None:
        assert (
            keccak256(b"").hex()
            == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        )

    def test_abc_vector(self) -> None:
        assert (
            keccak256(b"abc").hex()
            == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        )

    def test_long_input_spans_multiple_blocks(self) -> None:
        # 200-byte input exceeds the 136-byte rate, exercising multiple absorbs.
        data = bytes(range(256))[:200]
        digest = keccak256(data)
        assert len(digest) == 32
        # Deterministic. Recompute and compare.
        assert keccak256(data) == digest


class TestDeriveEcdsaAddress:
    # Real signing_public_key / signing_address pair from a NEAR attestation.
    PUBKEY = (
        "a31cdd4f9443ebc31cffffd688621a1807b41c2f02649881d010f881de0a5e94"
        "ddec8208161e8fa02ae3748700bf8be3333c9683d6e13e0bbe7e92ee7d2243b8"
    )
    ADDRESS = "56d070df1c6be444b007839ef9cf67cec7c12b8b"

    def test_derives_known_pair(self) -> None:
        assert derive_ecdsa_address(self.PUBKEY) == self.ADDRESS

    def test_accepts_0x04_uncompressed_prefix(self) -> None:
        with_prefix = "04" + self.PUBKEY
        assert derive_ecdsa_address(with_prefix) == derive_ecdsa_address(self.PUBKEY)

    def test_accepts_0x_prefix(self) -> None:
        assert derive_ecdsa_address("0x" + self.PUBKEY) == derive_ecdsa_address(
            self.PUBKEY
        )

    def test_rejects_wrong_length(self) -> None:
        assert derive_ecdsa_address("ab" * 10) is None

    def test_rejects_non_hex(self) -> None:
        assert derive_ecdsa_address("zz" * 32) is None


class TestSigningKeyBindsAddress:
    def test_matching_pair_passes(self) -> None:
        assert _signing_key_binds_address(_REAL_PUBKEY, _REAL_ADDRESS, "ecdsa") is True

    def test_mismatched_address_rejected(self) -> None:
        assert (
            _signing_key_binds_address(_REAL_PUBKEY, "0x" + "11" * 20, "ecdsa") is False
        )

    def test_malformed_pubkey_rejected(self) -> None:
        assert _signing_key_binds_address("ab" * 10, _REAL_ADDRESS, "ecdsa") is False

    def test_missing_address_rejected(self) -> None:
        assert _signing_key_binds_address(_REAL_PUBKEY, None, "ecdsa") is False

    def test_unknown_algo_rejected(self) -> None:
        # An algo we can't verify the key correspondence for is not recorded.
        assert _signing_key_binds_address(_REAL_PUBKEY, _REAL_ADDRESS, "rsa") is False


# Real ed25519 signing key from a NEAR inference attestation (glm-5-1): the
# signing identity IS the 32-byte public key, so signing_address == pubkey.
_ED25519_KEY = "40ef1aadbb12f26cf4c2d499b9e7a7b043da4388200715abed573fa135a561bb"


class TestSigningKeyBindsAddressEd25519:
    def test_matching_key_passes(self) -> None:
        # ed25519: signing_address == signing_public_key (no derivation).
        assert _signing_key_binds_address(_ED25519_KEY, _ED25519_KEY, "ed25519") is True

    def test_0x_prefixes_normalized(self) -> None:
        assert (
            _signing_key_binds_address(
                "0x" + _ED25519_KEY, "0x" + _ED25519_KEY, "ed25519"
            )
            is True
        )

    def test_mismatched_key_rejected(self) -> None:
        assert _signing_key_binds_address(_ED25519_KEY, "cd" * 32, "ed25519") is False

    def test_wrong_length_rejected(self) -> None:
        # A 64-byte (secp256k1) key is not a valid 32-byte ed25519 key.
        result = _signing_key_binds_address(_REAL_PUBKEY, _REAL_PUBKEY, "ed25519")
        assert result is False

    def test_missing_address_rejected(self) -> None:
        assert _signing_key_binds_address(_ED25519_KEY, None, "ed25519") is False


def test_missing_signing_algo_is_refused() -> None:
    """A response that names no scheme is not assumed to be ecdsa."""
    assert _signing_key_binds_address("ab" * 32, "ab" * 32, None) is False
