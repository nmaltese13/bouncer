"""Operator key management (Ed25519).

Threat model: the operator key signs audit entries and mandates. What a valid
signature proves is narrow and worth stating precisely:

- It proves a record was produced by a holder of this key and has not been
  altered *since it was written*.
- It proves nothing about whether the decision was correct, and nothing about
  an operator who was already compromised at the moment of writing. An attacker
  who holds the key can write a consistent, correctly-signed history.

The private key is written with mode 0600 and never leaves this process.

That protection is POSIX-only. On Windows the mode bits ``os.open`` accepts
are advisory — the file lands under inherited ACLs and ``st_mode`` reports
``-rw-rw-rw-`` regardless — so bouncer neither restricts the key nor can it
tell whether the key is exposed. On Windows, treat the key file as protected
only as far as the enclosing directory's ACL protects it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import BouncerError

#: Ed25519 detached signatures are a fixed width.
_SIGNATURE_BYTES = 64

__all__ = [
    "ExternalSigner",
    "KeyError_",
    "OperatorKey",
    "Signer",
    "VerifyKey",
    "key_id_for",
]


class KeyError_(BouncerError):
    """The operator key is missing, malformed, or unreadable."""


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """A short, stable fingerprint of a public key.

    Recorded on every audit row so a log signed under a rotated key can still
    be attributed to the key that signed it.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


class VerifyKey:
    """The public half. Enough to verify, never enough to sign."""

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public = public_key

    @classmethod
    def from_pem(cls, pem: bytes) -> VerifyKey:
        try:
            loaded = serialization.load_pem_public_key(pem)
        except (ValueError, TypeError) as exc:
            raise KeyError_(f"not a valid PEM public key: {exc}") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise KeyError_("public key is not Ed25519")
        return cls(loaded)

    @classmethod
    def from_file(cls, path: str | Path) -> VerifyKey:
        try:
            return cls.from_pem(Path(path).read_bytes())
        except OSError as exc:
            raise KeyError_(f"cannot read public key at {path}: {exc}") from exc

    @property
    def key_id(self) -> str:
        return key_id_for(self._public)

    def to_pem(self) -> bytes:
        return self._public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Constant-time signature check. Returns False rather than raising."""
        try:
            self._public.verify(signature, message)
        except InvalidSignature:
            return False
        return True


@runtime_checkable
class Signer(Protocol):
    """Something that can sign on the operator's behalf.

    The audit log and the mandate issuer depend on this, not on
    :class:`OperatorKey`, so the private key does not have to live inside this
    process. Three members are all the signing path ever needs.

    Threat model: widening this seam does not by itself improve anything — an
    in-process key remains the default. What it buys is that a signer backed by
    a TPM, an HSM or a hardware token can be substituted without the audit or
    mandate code changing, which turns the mitigation named in SECURITY.md from
    a design note into something an operator can actually deploy.
    """

    @property
    def key_id(self) -> str:
        """Short fingerprint of the public half, recorded on every audit row."""
        ...

    @property
    def verify_key(self) -> VerifyKey:
        """The public half, for verification."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Produce a detached Ed25519 signature over ``message``."""
        ...


class ExternalSigner:
    """Signs by invoking an external command; no private key in this process.

    The command receives the message to sign on stdin and writes the detached
    Ed25519 signature to stdout, either as 64 raw bytes or as base64. That is a
    small enough contract for a shell wrapper around ``pkcs11-tool``, a YubiKey
    agent, a TPM helper, or a signing service on a socket.

    Threat model: this narrows what a compromise of *this* process yields. An
    attacker with code execution can still ask the signer to sign whatever they
    like while they retain access — it is a signing oracle, not a vault — but
    they cannot copy the key out and forge history offline or after eviction.
    Against the failure the audit log is most exposed to, that is the difference
    between a permanent forgery capability and a temporary one.

    Every signature is verified against the public key before it is returned. A
    misconfigured or broken signer that emits garbage would otherwise write
    unverifiable rows, and the damage would only surface at the next
    ``bouncer verify`` — long after the evidence was needed.
    """

    def __init__(
        self,
        command: Sequence[str],
        public_key: VerifyKey,
        *,
        timeout: float = 10.0,
    ) -> None:
        if not command:
            raise KeyError_("external signer command must not be empty")
        self._command = list(command)
        self._public = public_key
        self._timeout = timeout

    @classmethod
    def from_public_pem(
        cls, command: Sequence[str], path: str | Path, *, timeout: float = 10.0
    ) -> ExternalSigner:
        """Build a signer that verifies against the public key at ``path``."""
        return cls(command, VerifyKey.from_file(path), timeout=timeout)

    @property
    def key_id(self) -> str:
        return self._public.key_id

    @property
    def verify_key(self) -> VerifyKey:
        return self._public

    def sign(self, message: bytes) -> bytes:
        try:
            completed = subprocess.run(  # noqa: S603 - the command is operator config
                self._command,
                input=message,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise KeyError_(
                f"external signer {self._command[0]!r} could not be run: {exc}"
            ) from exc

        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise KeyError_(
                f"external signer exited {completed.returncode}: {detail[:200]}"
            )

        signature = _decode_signature(completed.stdout)
        # Refusing here is the difference between one loud failure and a log
        # full of rows that will never verify.
        if not self._public.verify(signature, message):
            raise KeyError_(
                "external signer returned a signature that does not verify under "
                f"key {self.key_id}; refusing to record it"
            )
        return signature


def _decode_signature(raw: bytes) -> bytes:
    """Accept a detached Ed25519 signature as raw bytes or base64.

    Ed25519 signatures are always exactly 64 bytes, and base64 of 64 bytes is
    never 64 bytes, so the two encodings cannot be confused for one another.
    """
    if len(raw) == _SIGNATURE_BYTES:
        return raw
    try:
        decoded = base64.b64decode(raw.strip(), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise KeyError_(
            f"external signer produced {len(raw)} bytes, which is neither a raw "
            "64-byte Ed25519 signature nor valid base64"
        ) from exc
    if len(decoded) != _SIGNATURE_BYTES:
        raise KeyError_(
            f"external signer produced a {len(decoded)}-byte signature; "
            f"Ed25519 signatures are {_SIGNATURE_BYTES} bytes"
        )
    return decoded


class OperatorKey:
    """The signing key held by the single trusted operator."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key

    # -- lifecycle --------------------------------------------------------

    @classmethod
    def generate(cls, path: str | Path | None = None) -> OperatorKey:
        """Create a new key, writing it to ``path`` with mode 0600 if given."""
        key = cls(Ed25519PrivateKey.generate())
        if path is not None:
            key.save(path)
        return key

    @classmethod
    def load(cls, path: str | Path) -> OperatorKey:
        file_path = Path(path).expanduser()
        try:
            pem = file_path.read_bytes()
        except OSError as exc:
            raise KeyError_(
                f"cannot read operator key at {file_path}: {exc}; "
                "run `bouncer keygen` to create one"
            ) from exc
        cls._warn_if_world_readable(file_path)
        try:
            loaded = serialization.load_pem_private_key(pem, password=None)
        except (ValueError, TypeError) as exc:
            raise KeyError_(f"not a valid PEM private key: {exc}") from exc
        if not isinstance(loaded, Ed25519PrivateKey):
            raise KeyError_("operator key is not Ed25519")
        return cls(loaded)

    @classmethod
    def load_or_generate(cls, path: str | Path) -> OperatorKey:
        file_path = Path(path).expanduser()
        if file_path.exists():
            return cls.load(file_path)
        return cls.generate(file_path)

    def save(self, path: str | Path) -> Path:
        """Write the private key as PEM with restrictive permissions."""
        file_path = Path(path).expanduser()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        pem = self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Create with 0600 from the outset rather than chmod-ing afterwards,
        # which would leave a window where the key is world-readable. Windows
        # ignores the mode argument; see the module docstring.
        descriptor = os.open(
            file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pem)
        return file_path

    @staticmethod
    def _warn_if_world_readable(path: Path) -> None:
        # Windows synthesises st_mode: every readable file reports group and
        # other read, so this check would fire on every load while telling the
        # operator nothing about the actual ACL. A warning that is always wrong
        # trains people to ignore it, so stay quiet rather than cry wolf. The
        # exposure this leaves is stated in the module docstring.
        if os.name == "nt":
            return
        try:
            mode = path.stat().st_mode
        except OSError:  # pragma: no cover - stat succeeded moments earlier
            return
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            import warnings

            warnings.warn(
                f"operator key {path} is readable by other users (mode "
                f"{stat.filemode(mode)}); anyone who can read it can forge "
                "audit entries and mandates",
                stacklevel=3,
            )

    # -- use --------------------------------------------------------------

    @property
    def key_id(self) -> str:
        return key_id_for(self._private.public_key())

    @property
    def verify_key(self) -> VerifyKey:
        return VerifyKey(self._private.public_key())

    def public_pem(self) -> bytes:
        return self.verify_key.to_pem()

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)

    def verify(self, signature: bytes, message: bytes) -> bool:
        return self.verify_key.verify(signature, message)


def load_signer(
    key_path: str | Path,
    *,
    command: Sequence[str] | None = None,
    public_key_path: str | Path | None = None,
    create: bool = False,
) -> Signer:
    """Build the signer an operator has configured.

    Defaults to an in-process :class:`OperatorKey`, which is what a single
    trusted operator on a trusted machine wants. Supplying ``command`` switches
    to an :class:`ExternalSigner`, so the private key never enters this process
    and cannot be copied out of it.

    An external signer requires the matching public key: bouncer must be able to
    verify what the signer hands back, and it needs the key id for the audit
    rows. Refusing without one is deliberate -- inferring it from whatever the
    signer first returns would mean trusting an unverified signature to
    establish the identity every later signature is checked against.

    Args:
        create: Generate an operator key when none exists. Off by default,
            because a missing key usually means the wrong home directory, and
            silently minting a replacement would leave every previously signed
            audit row unverifiable under the new one. Only first-run paths
            pass True.
    """
    if command:
        if public_key_path is None:
            raise KeyError_(
                "an external signer needs the matching public key; set the "
                "public key path alongside the signer command"
            )
        return ExternalSigner.from_public_pem(command, public_key_path)
    if create:
        return OperatorKey.load_or_generate(key_path)
    return OperatorKey.load(key_path)
