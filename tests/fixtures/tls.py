"""Test certificate authority for the fixture origins (trustme).

One CA signs one leaf certificate that covers every fake HTTPS hostname in the
test world. A second, untrusted CA signs the certificate for ``badcert.test`` so
tests can provoke a TLS verification failure end to end.

Clients trust the CA as follows (tests only):
- httpx: ``verify=world.tls.client_context()`` (an ``ssl.SSLContext``);
- requests: ``verify=world.ca_pem``;
- curl: ``--cacert <world.ca_pem>``;
- Chromium: ``new_context(ignore_https_errors=True)``; see the README for the
  optional ``--ignore-certificate-errors-spki-list`` launch argument.
"""

from __future__ import annotations

import base64
import hashlib
import ssl
from pathlib import Path

import trustme
from cryptography import x509
from cryptography.hazmat.primitives import serialization

#: Hostnames covered by the trusted leaf certificate.
TRUSTED_NAMES: tuple[str, ...] = (
    "origin-a.test",
    "origin-b.test",
    "origin-c.test",
    "api.openai.com",
    "optimizationguide-pa.googleapis.com",
    "update.googleapis.com",
    "clients2.google.com",
    "clients2.googleusercontent.com",
    "edgedl.me.gvt1.com",
    "safebrowsing.googleapis.com",
    "localhost",
    "127.0.0.1",
)

#: Hostname whose certificate chains to an untrusted CA.
BAD_CERT_NAME = "badcert.test"


class TestCA:
    """Holds the trusted CA, the leaf certificate and the untrusted CA."""

    __test__ = False  # not a pytest test class

    def __init__(self, workdir: Path) -> None:
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.ca = trustme.CA(organization_name="scrapescope fixture CA")
        self.leaf = self.ca.issue_cert(*TRUSTED_NAMES)
        self.bad_ca = trustme.CA(organization_name="scrapescope untrusted fixture CA")
        self.bad_leaf = self.bad_ca.issue_cert(BAD_CERT_NAME)
        self.ca_pem_path = self.workdir / "fixture-ca.pem"
        self.ca.cert_pem.write_to_path(str(self.ca_pem_path))
        self.bad_ca_pem_path = self.workdir / "fixture-untrusted-ca.pem"
        self.bad_ca.cert_pem.write_to_path(str(self.bad_ca_pem_path))

    @property
    def ca_pem(self) -> str:
        """Filesystem path of the trusted CA certificate (PEM)."""
        return str(self.ca_pem_path)

    def server_context(self, *, bad: bool = False) -> ssl.SSLContext:
        """Server-side context for the origins; HTTP/1.1 only via ALPN."""
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        (self.bad_leaf if bad else self.leaf).configure_cert(ctx)
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx

    def client_context(self) -> ssl.SSLContext:
        """Client-side context that trusts only the fixture CA."""
        ctx = ssl.create_default_context(cafile=self.ca_pem)
        return ctx

    def leaf_spki_sha256_b64(self) -> str:
        """Base64 SHA-256 of the trusted leaf's SubjectPublicKeyInfo.

        Suitable for Chromium's ``--ignore-certificate-errors-spki-list``.
        """
        pem = self.leaf.cert_chain_pems[0].bytes()
        cert = x509.load_pem_x509_certificate(pem)
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
