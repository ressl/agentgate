"""Ed25519 audit trail signing — cryptographic tamper-proof event log."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


class AuditSigner:
    """Sign and verify audit log entries with Ed25519."""

    def __init__(self, key_path: str | Path | None = None) -> None:
        self._key_path = Path(key_path) if key_path else Path("mcp-firewall.key")
        self._pub_path = self._key_path.with_suffix(".pub")
        self._private_key: Ed25519PrivateKey | None = None
        self._public_key: Ed25519PublicKey | None = None

        if self._key_path.exists():
            self._load_keys()
        else:
            self._generate_keys()

    def _generate_keys(self) -> None:
        """Generate new Ed25519 keypair."""
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

        # Save private key
        pem = self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        self._key_path.write_bytes(pem)
        self._key_path.chmod(0o600)

        # Save public key
        pub_pem = self._public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        self._pub_path.write_bytes(pub_pem)

    def _load_keys(self) -> None:
        """Load existing keypair."""
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        pem = self._key_path.read_bytes()
        self._private_key = load_pem_private_key(pem, password=None)  # type: ignore
        self._public_key = self._private_key.public_key()  # type: ignore

    def sign(self, data: str) -> str:
        """Sign data, return base64-encoded signature."""
        if not self._private_key:
            raise RuntimeError("No signing key loaded")
        sig = self._private_key.sign(data.encode())
        return base64.b64encode(sig).decode()

    def verify(self, data: str, signature_b64: str) -> bool:
        """Verify a signature."""
        if not self._public_key:
            raise RuntimeError("No public key loaded")
        try:
            sig = base64.b64decode(signature_b64)
            self._public_key.verify(sig, data.encode())
            return True
        except Exception:
            return False

    @property
    def public_key_pem(self) -> str:
        """Get public key as PEM string."""
        if not self._public_key:
            return ""
        return self._public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
