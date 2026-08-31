"""Runtime configuration: where bouncer keeps its files.

Everything lives under a single directory (``BOUNCER_HOME``, default
``~/.bouncer``) so an operator can back up, inspect, or destroy the whole state
of the system in one place. Nothing here talks to a network service; there is no
server to configure.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["BouncerConfig", "DEFAULT_HOME"]

DEFAULT_HOME = Path("~/.bouncer")

#: Long-poll ceiling for `/authorize` when a decision needs a human. On expiry
#: the request is DENIED. It must never time out into an allow.
DEFAULT_APPROVAL_TIMEOUT = 300.0


@dataclass(frozen=True)
class BouncerConfig:
    """Resolved paths and tunables for one bouncer instance."""

    home: Path = field(default_factory=lambda: _env_path("BOUNCER_HOME", DEFAULT_HOME))
    policy_path: Path | None = None
    db_path: Path | None = None
    key_path: Path | None = None
    approval_timeout: float = DEFAULT_APPROVAL_TIMEOUT
    webhook_url: str | None = None
    #: Command that signs on the operator's behalf. When set, the private
    #: key never enters this process. See bouncer.keys.ExternalSigner.
    signer_command: str | None = None
    #: Public key matching the external signer, required alongside it.
    public_key_path: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "home", Path(self.home).expanduser())
        for name, default in (
            ("policy_path", self.home / "policy.yaml"),
            ("db_path", self.home / "bouncer.db"),
            ("key_path", self.home / "operator.pem"),
        ):
            current = getattr(self, name)
            resolved = Path(current).expanduser() if current is not None else default
            object.__setattr__(self, name, resolved)

    @classmethod
    def from_env(cls) -> BouncerConfig:
        """Build a config from ``BOUNCER_*`` environment variables."""
        timeout_raw = os.environ.get("BOUNCER_APPROVAL_TIMEOUT")
        try:
            timeout = float(timeout_raw) if timeout_raw else DEFAULT_APPROVAL_TIMEOUT
        except ValueError:
            timeout = DEFAULT_APPROVAL_TIMEOUT
        return cls(
            home=_env_path("BOUNCER_HOME", DEFAULT_HOME),
            policy_path=_optional_env_path("BOUNCER_POLICY"),
            db_path=_optional_env_path("BOUNCER_DB"),
            key_path=_optional_env_path("BOUNCER_KEY"),
            approval_timeout=timeout,
            webhook_url=os.environ.get("BOUNCER_WEBHOOK_URL") or None,
            signer_command=os.environ.get("BOUNCER_SIGNER_COMMAND") or None,
            public_key_path=_optional_env_path("BOUNCER_PUBLIC_KEY"),
        )

    def ensure_home(self) -> Path:
        """Create the home directory, owner-accessible only."""
        assert self.home is not None
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        return self.home

    @property
    def db_url(self) -> str:
        return f"sqlite+pysqlite:///{self.db_path}"

    @property
    def signer_argv(self) -> list[str] | None:
        """The signer command split into argv, or None for an in-process key."""
        return shlex.split(self.signer_command) if self.signer_command else None


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    return Path(raw).expanduser() if raw else default.expanduser()


def _optional_env_path(name: str) -> Path | None:
    raw = os.environ.get(name)
    return Path(raw).expanduser() if raw else None

