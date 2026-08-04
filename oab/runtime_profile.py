from __future__ import annotations

import hashlib
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

_ALLOWED_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh"}
_CREDENTIAL_FILES = (
    "auth.json",
    "auth.lock",
    ".env",
    ".anthropic_oauth.json",
)


@dataclass(frozen=True)
class PinnedHermesRuntime:
    home: Path
    reasoning_effort: str
    config_sha256: str


def _source_home(value: str | Path | None) -> Path:
    if value is not None:
        return Path(value).expanduser().resolve(strict=True)
    configured = os.environ.get("HERMES_HOME", "").strip()
    candidate = Path(configured).expanduser() if configured else Path.home() / ".hermes"
    return candidate.resolve(strict=True)


@contextmanager
def pinned_hermes_runtime(
    reasoning_effort: str,
    *,
    source_home: str | Path | None = None,
) -> Iterator[PinnedHermesRuntime]:
    effort = reasoning_effort.strip().lower()
    if effort not in _ALLOWED_EFFORTS:
        raise ValueError("reasoning_effort_invalid")
    source = _source_home(source_home)
    source_config = source / "config.yaml"
    if not source_config.is_file() or source_config.is_symlink():
        raise ValueError("source_hermes_config_invalid")
    try:
        config = yaml.safe_load(source_config.read_bytes()) or {}
    except (OSError, yaml.YAMLError):
        raise ValueError("source_hermes_config_invalid") from None
    if not isinstance(config, dict):
        raise ValueError("source_hermes_config_invalid")
    agent = config.setdefault("agent", {})
    if not isinstance(agent, dict):
        raise ValueError("source_hermes_config_invalid")
    agent["reasoning_effort"] = effort
    # One OAB controller decision is exactly one provider call. Prevent the
    # Hermes agent loop from issuing tool-followup or retry turns internally.
    agent["max_iterations"] = 1
    config_bytes = yaml.safe_dump(
        config,
        sort_keys=True,
        allow_unicode=True,
        default_flow_style=False,
    ).encode("utf-8")
    config_sha256 = "sha256:" + hashlib.sha256(config_bytes).hexdigest()

    with tempfile.TemporaryDirectory(prefix="oab-hermes-runtime-") as td:
        home = Path(td).resolve()
        home.chmod(0o700)
        runtime_config = home / "config.yaml"
        runtime_config.write_bytes(config_bytes)
        runtime_config.chmod(0o600)
        for name in _CREDENTIAL_FILES:
            source_file = source / name
            if source_file.is_file():
                (home / name).symlink_to(source_file.resolve(strict=True))
        yield PinnedHermesRuntime(
            home=home,
            reasoning_effort=effort,
            config_sha256=config_sha256,
        )
