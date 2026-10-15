# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for the certificate-chain half of verifier.verifications.tls.

These build real certificate chains; the trust store is monkeypatched to
contain the locally minted root.
"""

import asyncio
import datetime
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import Store

from verifier.verifications import tls
from verifier.verifications.tls import (
    _spki_hash,
    compute_spki_hash_from_pem,
    parse_certificate_chain,
    verify_certificate_key,
)

NOW = datetime.datetime.now(datetime.UTC)
DAY = datetime.timedelta(days=1)
DOMAIN = "cloud-api.example"

PrivKey = Any


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _new_key(use_rsa: bool = False) -> PrivKey:
    if use_rsa:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP256R1())


def _make_cert(
    subject_cn: str,
    issuer: tuple[x509.Certificate, PrivKey] | None = None,
    *,
    is_ca: bool = False,
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    use_rsa: bool = False,
) -> tuple[x509.Certificate, PrivKey]:
    """Mint a Web PKI-shaped certificate. Self-signed when issuer is None.

    A leaf carries ``subject_cn`` as its DNS name and serverAuth usage.
    """
    key = _new_key(use_rsa)
    issuer_cert, issuer_key = issuer if issuer else (None, key)
    issuer_name = issuer_cert.subject if issuer_cert else _name(subject_cn)
    issuer_public = issuer_key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (NOW - DAY))
        .not_valid_after(not_after or (NOW + 90 * DAY))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=not is_ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if not is_ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(subject_cn)]), critical=False
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def _pem(*certs: x509.Certificate) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


def _chain(
    *, use_rsa: bool = False, **leaf_kwargs: Any
) -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    """leaf -> intermediate -> root, each correctly signed by the next."""
    root = _make_cert("Test Root", is_ca=True, use_rsa=use_rsa)
    inter = _make_cert("Test Intermediate", root, is_ca=True, use_rsa=use_rsa)
    leaf, _ = _make_cert(DOMAIN, inter, use_rsa=use_rsa, **leaf_kwargs)
    return leaf, inter[0], root[0]


@pytest.fixture(scope="module")
def chain() -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    return _chain()


@pytest.fixture(autouse=True)
def _reset_trust_store() -> Iterator[None]:
    """The real store is lru_cached; make sure a patched one never leaks."""
    tls._trust_store.cache_clear()
    yield
    tls._trust_store.cache_clear()


@pytest.fixture
def trust(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Return a function that makes the given certs the entire trust store."""

    def _trust(*certs: x509.Certificate) -> None:
        store = Store(list(certs))
        monkeypatch.setattr(tls, "_trust_store", lambda: store)

    return _trust


class TestParseCertificateChain:
    def test_parses_every_certificate_in_order(self, chain: Any) -> None:
        leaf, inter, root = chain
        parsed = parse_certificate_chain(_pem(leaf, inter, root))
        expected = [leaf.subject, inter.subject, root.subject]
        assert [c.subject for c in parsed] == expected

    def test_skips_a_corrupt_block_and_keeps_the_rest(self, chain: Any) -> None:
        leaf, _, _ = chain
        corrupt = "-----BEGIN CERTIFICATE-----\nd29yc2U=\n-----END CERTIFICATE-----\n"
        parsed = parse_certificate_chain(_pem(leaf) + corrupt)
        assert [c.subject for c in parsed] == [leaf.subject]

    def test_returns_empty_for_non_pem_input(self) -> None:
        assert parse_certificate_chain("not a certificate") == []


class TestVerifyCertificateKey:
    def test_accepts_a_full_chain_to_a_trusted_root(
        self, chain: Any, trust: Any
    ) -> None:
        leaf, inter, root = chain
        trust(root)
        assert verify_certificate_key(_pem(leaf, inter, root), DOMAIN) is True
        # The root need not be in the evidence when the store holds it.
        assert verify_certificate_key(_pem(leaf, inter), DOMAIN) is True

    def test_accepts_an_rsa_chain(self, trust: Any) -> None:
        leaf, inter, root = _chain(use_rsa=True)
        trust(root)
        assert verify_certificate_key(_pem(leaf, inter, root), DOMAIN) is True

    def test_rejects_a_chain_whose_root_is_not_trusted(
        self, chain: Any, trust: Any
    ) -> None:
        leaf, inter, root = chain
        other, _ = _make_cert("Unrelated Root", is_ca=True)
        trust(other)
        with pytest.raises(RuntimeError, match="Certificate verification failed"):
            verify_certificate_key(_pem(leaf, inter, root), DOMAIN)

    def test_rejects_a_root_with_a_trusted_name_but_another_key(
        self, chain: Any, trust: Any
    ) -> None:
        leaf, inter, root = chain
        impostor, _ = _make_cert("Test Root", is_ca=True)
        assert impostor.subject == root.subject
        trust(impostor)
        with pytest.raises(RuntimeError, match="Certificate verification failed"):
            verify_certificate_key(_pem(leaf, inter, root), DOMAIN)

    def test_rejects_a_link_not_signed_by_the_next(
        self, chain: Any, trust: Any
    ) -> None:
        leaf, _, root = chain
        trust(root)
        # leaf was signed by the intermediate, not the root.
        with pytest.raises(RuntimeError, match="Certificate verification failed"):
            verify_certificate_key(_pem(leaf, root), DOMAIN)

    def test_rejects_a_leaf_used_as_an_intermediate(self, trust: Any) -> None:
        root = _make_cert("Test Root", is_ca=True)
        not_ca = _make_cert("other.example", root)
        leaf, _ = _make_cert(DOMAIN, not_ca)
        trust(root[0])
        with pytest.raises(RuntimeError, match="Certificate verification failed"):
            verify_certificate_key(_pem(leaf, not_ca[0], root[0]), DOMAIN)

    def test_rejects_another_domain(self, chain: Any, trust: Any) -> None:
        leaf, inter, root = chain
        trust(root)
        with pytest.raises(RuntimeError, match="Certificate verification failed"):
            verify_certificate_key(_pem(leaf, inter, root), "other.example")

    @pytest.mark.parametrize(
        ("not_before", "not_after"),
        [(NOW - 10 * DAY, NOW - DAY), (NOW + DAY, NOW + 10 * DAY)],
        ids=["expired", "not-yet-valid"],
    )
    def test_rejects_a_leaf_outside_its_validity(
        self, trust: Any, not_before: datetime.datetime, not_after: datetime.datetime
    ) -> None:
        leaf, inter, root = _chain(not_before=not_before, not_after=not_after)
        trust(root)
        with pytest.raises(RuntimeError, match="Certificate verification failed"):
            verify_certificate_key(_pem(leaf, inter, root), DOMAIN)

    def test_rejects_unparseable_input(self) -> None:
        with pytest.raises(RuntimeError, match="no certificate") as excinfo:
            verify_certificate_key("not a certificate", DOMAIN)
        assert str(excinfo.value).count("Certificate verification failed") == 1


class TestSpkiHashes:
    def test_chain_hash_is_the_leaf_not_the_root(self, chain: Any) -> None:
        leaf, inter, root = chain
        assert compute_spki_hash_from_pem(_pem(leaf, inter, root)) == _spki_hash(leaf)

    def test_hash_is_lowercase_hex_sha256(self, chain: Any) -> None:
        leaf, _, _ = chain
        digest = _spki_hash(leaf)
        assert len(digest) == 64
        assert digest == digest.lower()
        assert all(c in "0123456789abcdef" for c in digest)

    def test_distinct_keys_hash_differently(self, chain: Any) -> None:
        leaf, inter, _ = chain
        assert _spki_hash(leaf) != _spki_hash(inter)

    def test_empty_chain_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            compute_spki_hash_from_pem("not a certificate")


class TestVerifyCertificateFingerprintBinding:
    """The attested-SPKI binding in verify_certificate; absent must fail."""

    @staticmethod
    def _run(
        monkeypatch: pytest.MonkeyPatch,
        evidence_pem: str,
        attested: str | None,
    ) -> tls.TLSVerificationResult:
        async def fake_connection(domain: str, pem: str) -> tls.TLSVerificationResult:
            return {
                "type": "Domain TLS Certificate",
                "domain": domain,
                "certificate_verified": True,
                "fingerprint_matches": True,
                "attestation_fingerprint_matches": False,
                "dns_caa_verified": False,
            }

        async def fake_caa(domain: str) -> bool:
            return True

        monkeypatch.setattr(tls, "verify_tls_connection", fake_connection)
        monkeypatch.setattr(tls, "verify_dns_caa", fake_caa)
        return asyncio.run(
            tls.verify_certificate("cloud-api.example", evidence_pem, attested)
        )

    def test_absent_fingerprint_fails_closed(
        self, chain: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        leaf, inter, root = chain
        result = self._run(monkeypatch, _pem(leaf, inter, root), None)
        assert result["attestation_fingerprint_matches"] is False
        # and it must poison the headline fingerprint verdict too
        assert result["fingerprint_matches"] is False

    def test_matching_fingerprint_passes(
        self, chain: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        leaf, inter, root = chain
        result = self._run(monkeypatch, _pem(leaf, inter, root), _spki_hash(leaf))
        assert result["attestation_fingerprint_matches"] is True
        assert result["fingerprint_matches"] is True

    def test_colon_separated_uppercase_fingerprint_is_normalised(
        self, chain: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        leaf, inter, root = chain
        raw = _spki_hash(leaf).upper()
        colonised = ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))
        result = self._run(monkeypatch, _pem(leaf, inter, root), colonised)
        assert result["attestation_fingerprint_matches"] is True

    def test_fingerprint_for_a_different_key_fails(
        self, chain: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        leaf, inter, root = chain
        # The intermediate's SPKI, not the leaf's: a quote bound to one backend
        # attached to another backend's certificate.
        result = self._run(monkeypatch, _pem(leaf, inter, root), _spki_hash(inter))
        assert result["attestation_fingerprint_matches"] is False
        assert result["fingerprint_matches"] is False

    def test_unparseable_evidence_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._run(monkeypatch, "not a certificate", "ab" * 32)
        assert result["attestation_fingerprint_matches"] is False
