# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""TLS certificate verification for the gateway domain."""

import asyncio
import re
import socket
import ssl
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import TypedDict

import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from ..utils import get_http_session, get_logger

logger = get_logger(__name__)

_CAA_RRTYPE = 257
_EXPECTED_CA = "letsencrypt.org"


class TLSVerificationResult(TypedDict):
    type: str
    domain: str
    certificate_verified: bool
    fingerprint_matches: bool
    attestation_fingerprint_matches: bool
    dns_caa_verified: bool


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get the SHA256 fingerprint of a certificate in OpenSSL
    format (colon-separated hex, uppercase)."""
    return str(cert.fingerprint(hashes.SHA256()).hex(":").upper())


async def fetch_live_certificate(domain: str, port: int = 443) -> x509.Certificate:
    """Fetch the certificate from a live server via a verified TLS connection."""

    def _fetch_cert() -> x509.Certificate:
        conn = socket.create_connection((domain, port), timeout=10)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_default_certs()
            ssock = context.wrap_socket(conn, server_hostname=domain)
            try:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    raise ValueError(f"No certificate returned by {domain}:{port}")
                return x509.load_der_x509_certificate(cert_der)
            finally:
                ssock.close()
        finally:
            conn.close()

    try:
        return await asyncio.to_thread(_fetch_cert)
    except ssl.SSLCertVerificationError as e:
        raise RuntimeError(
            f"Certificate verification failed for {domain}:{port}: {e}"
        ) from e
    except (TimeoutError, socket.gaierror, OSError) as e:
        raise RuntimeError(f"Connection to {domain}:{port} failed: {e}") from e


def parse_certificate_chain(cert_chain_pem: str) -> list[x509.Certificate]:
    """Parse PEM certificate chain into list of X509 certificates."""
    pem_certificate_regex = (
        r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----"
    )
    parsed_certificates = []

    for certificate_match in re.finditer(pem_certificate_regex, cert_chain_pem):
        try:
            cert_pem = certificate_match.group(0)
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            parsed_certificates.append(cert)
        except Exception as parse_error:
            logger.error(f"Failed to parse certificate from PEM: {parse_error}")

    return parsed_certificates


def _spki_hash(certificate: x509.Certificate) -> str:
    """SHA256 of a certificate's SubjectPublicKeyInfo, lowercase hex."""
    spki_der = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(spki_der).hexdigest().lower()


def compute_spki_hash_from_pem(cert_chain_pem: str) -> str:
    """Compute SHA256 hash of the leaf certificate's SubjectPublicKeyInfo."""
    certificates = parse_certificate_chain(cert_chain_pem)
    if not certificates:
        raise ValueError("Certificate chain is empty")
    return _spki_hash(certificates[0])


@lru_cache(maxsize=1)
def _trust_store() -> Store:
    """The Mozilla root program, as shipped by ``certifi``.

    Parsed per-certificate so one malformed root is skipped rather than fatal.
    An empty store raises.
    """
    roots = parse_certificate_chain(Path(certifi.where()).read_text())
    if not roots:
        raise RuntimeError(
            f"No usable CA certificates in the trust store at {certifi.where()};"
            " cannot establish TLS root trust"
        )
    return Store(roots)


def verify_certificate_key(certificate_pem: str, domain: str) -> bool:
    """Validate the evidence chain for ``domain`` up to a trusted root.

    RFC 5280 path validation: every signature, every validity period, CA and
    key-usage constraints on each issuer, and the leaf's name for ``domain``.
    """
    chain = parse_certificate_chain(certificate_pem)
    if not chain:
        raise RuntimeError(
            "Certificate verification failed: no certificate in the evidence"
        )
    verifier = (
        PolicyBuilder()
        .store(_trust_store())
        .build_server_verifier(x509.DNSName(domain))
    )
    try:
        verifier.verify(chain[0], chain[1:])
    except VerificationError as e:
        raise RuntimeError(f"Certificate verification failed: {e}") from e
    return True


async def compare_certificate_fingerprints(domain: str, evidence_cert_pem: str) -> bool:
    """Compare the certificate fingerprint from live server with
    evidence certificate."""
    try:
        evidence_cert_chain = parse_certificate_chain(evidence_cert_pem)
        if len(evidence_cert_chain) == 0:
            raise RuntimeError("Failed to parse evidence certificate")
        evidence_leaf_cert = evidence_cert_chain[0]
        evidence_fingerprint = get_certificate_fingerprint(evidence_leaf_cert)

        logger.info(f"Fetching certificate from live server: {domain}:443")
        live_cert = await fetch_live_certificate(domain, 443)
        live_fingerprint = get_certificate_fingerprint(live_cert)

        matches = evidence_fingerprint == live_fingerprint
        logger.info(f"Fingerprints match: {matches}")

        if not matches:
            logger.warning("⚠️  Certificate fingerprint mismatch!")
            logger.warning(
                "   The live server's certificate differs from the evidence"
                " certificate in the attestation report."
            )
            logger.warning(
                f"   Evidence cert (from report)  SHA256: {evidence_fingerprint}"
            )
            logger.warning(
                f"   Live cert (fresh connection) SHA256: {live_fingerprint}"
            )
            logger.warning(
                "   A load balancer whose replicas each hold their own"
                " certificate causes this, and so does a man-in-the-middle;"
                " the two look the same from here, so this fails closed."
                " Probing repeatedly shows which certificates %s serves:"
                " echo | openssl s_client -connect %s:443 2>/dev/null"
                " | openssl x509 -noout -fingerprint -sha256",
                domain,
                domain,
            )

        return matches
    except RuntimeError:
        raise
    except Exception as error:
        logger.error("Certificate fingerprint comparison failed: %s", error)
        raise RuntimeError(
            f"Certificate fingerprint comparison failed: {error}"
        ) from error


async def verify_tls_connection(
    domain: str, evidence_cert_pem: str
) -> TLSVerificationResult:
    """Verify the evidence certificate and compare it to the live server's."""
    result: TLSVerificationResult = {
        "type": "Domain TLS Certificate",
        "domain": domain,
        "certificate_verified": False,
        "fingerprint_matches": False,
        "attestation_fingerprint_matches": False,
        "dns_caa_verified": False,
    }

    try:
        cert_verified = verify_certificate_key(evidence_cert_pem, domain)
        result["certificate_verified"] = cert_verified
        if not cert_verified:
            logger.warning("Certificate verification failed")
    except Exception as error:
        logger.error(f"Certificate verification error: {error}")
        raise RuntimeError(f"Certificate verification failed: {error}") from error

    try:
        result["fingerprint_matches"] = await compare_certificate_fingerprints(
            domain, evidence_cert_pem
        )
    except Exception as error:
        logger.error(f"Failed to compare certificate fingerprints: {error}")
        raise RuntimeError(
            f"Failed to compare certificate fingerprints: {error}"
        ) from error

    return result


async def verify_dns_caa(domain: str) -> bool:
    """Verify the domain's CAA issuance records allow only the expected CA.

    Every ``issue`` and ``issuewild`` record must name the expected CA or
    forbid issuance (``;``), and at least one ``issue`` record must name it.
    Other tags, such as ``iodef``, do not grant issuance and are ignored. An
    empty CAA set means any CA may issue, so it fails.
    """
    dns_url = f"https://dns.google/resolve?name={domain}&type=CAA"
    try:
        response = await asyncio.to_thread(
            lambda: get_http_session().get(dns_url, timeout=10)
        )
        if not response.ok:
            logger.error(
                "DNS CAA query failed for %s: HTTP %s", domain, response.status_code
            )
            return False
        data = response.json()
    except Exception as error:
        logger.error("DNS CAA query failed for %s: %s", domain, error)
        return False

    # Data looks like '0 issue "letsencrypt.org; validationmethods=dns-01"'.
    # Exact match: a substring test would accept "letsencrypt.org.attacker.example".
    issuance: list[tuple[str, str, str]] = []
    for record in data.get("Answer", []):
        if record.get("type") != _CAA_RRTYPE:
            continue
        raw = str(record.get("data", ""))
        parts = raw.split(None, 2)
        tag = parts[1].lower() if len(parts) > 1 else ""
        if tag not in ("issue", "issuewild"):
            continue
        match = re.search(r'"([^"]*)"', raw)
        value = match.group(1) if match else (parts[2] if len(parts) > 2 else "")
        issuer = value.split(";", 1)[0].strip().rstrip(".").lower()
        issuance.append((tag, issuer, raw))
    if not issuance:
        logger.error("❌ No CAA issue records found for %s. Any CA may issue", domain)
        return False

    unauthorized = [
        raw for _, issuer, raw in issuance if issuer not in ("", _EXPECTED_CA)
    ]
    if unauthorized or not any(
        tag == "issue" and issuer == _EXPECTED_CA for tag, issuer, _ in issuance
    ):
        logger.error(
            "❌ CAA records for %s do not authorize only %s: %s",
            domain,
            _EXPECTED_CA,
            unauthorized or [raw for *_, raw in issuance],
        )
        return False

    logger.info("DNS CAA records authorize %s for %s ✅", _EXPECTED_CA, domain)
    return True


async def verify_certificate(
    domain: str, evidence_cert_pem: str, attestation_fingerprint: str | None = None
) -> TLSVerificationResult:
    """Verify a domain's TLS certificate, CAA records, and attested SPKI hash."""
    logger.info("\n🔐 TLS certificate")
    result = await verify_tls_connection(domain, evidence_cert_pem)
    result["dns_caa_verified"] = await verify_dns_caa(domain)

    # Fail closed: a missing fingerprint must not skip the quote-to-TLS binding.
    attestation_fingerprint_matches = False
    if attestation_fingerprint:
        normalized = attestation_fingerprint.replace(":", "").strip().lower()
        try:
            evidence_spki_hash = compute_spki_hash_from_pem(evidence_cert_pem)
            attestation_fingerprint_matches = normalized == evidence_spki_hash
            if attestation_fingerprint_matches:
                logger.info("Attested TLS fingerprint matches evidence certificate ✅")
            else:
                logger.warning(
                    "⚠️ TLS fingerprint mismatch: the TDX quote binds SPKI %s"
                    " but the evidence certificate's SPKI hash is %s. Both came"
                    " from the same gateway response, so the quote does not"
                    " vouch for this certificate. One cause is a gateway that"
                    " pairs a quote from one backend with a certificate from"
                    " another.",
                    normalized,
                    evidence_spki_hash,
                )
        except Exception as error:
            logger.error(
                "Failed to compute SPKI hash for attested certificate: %s", error
            )
            attestation_fingerprint_matches = False
    else:
        logger.error(
            "❌ No attested TLS fingerprint in the response, so the TDX quote"
            " cannot be bound to this TLS channel. Request the report with"
            " include_tls_fingerprint=true; if the fingerprint stays absent,"
            " the gateway cannot prove the attested CVM terminates this"
            " connection."
        )

    result["attestation_fingerprint_matches"] = attestation_fingerprint_matches
    result["fingerprint_matches"] = (
        result["fingerprint_matches"] and attestation_fingerprint_matches
    )
    return result
