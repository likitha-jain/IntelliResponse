"""Configuration for IntelliResponse.

Reads a local ``.env`` file (if present) and the process environment. No extra
dependency is required, which keeps the demo clone-and-run friendly.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
APP_NAME = "IntelliResponse"
APP_VERSION = "1.1.0"


def load_dotenv(path: Path | None = None) -> None:
    """Minimal ``.env`` loader. Existing environment variables win."""
    path = path or ROOT / ".env"
    if not path.exists():
        return
    try:
        if path.stat().st_size > 64_000:
            return
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validated_url(value: str | None, default: str | None = None) -> str | None:
    """Return ``value`` only if it is a safe http(s) URL, else ``default``.

    Credentials and incident content are sent to these endpoints, so plain HTTP is
    only accepted for loopback hosts (or when IR_ALLOW_INSECURE_URLS=1), and
    URLs that embed credentials are rejected.
    """
    if not value:
        return default
    try:
        parts = urlparse(value.strip())
        host = (parts.hostname or "").lower()
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return default
    if parts.scheme not in {"http", "https"} or not host or parts.username or parts.password:
        return default
    if parts.scheme == "http" and host not in _LOCAL_HOSTS and not _as_bool(os.getenv("IR_ALLOW_INSECURE_URLS")):
        return default
    return value.strip().rstrip("/")


@dataclass(frozen=True)
class Settings:
    """Runtime settings resolved once per Memory instance."""

    app_name: str = APP_NAME
    app_version: str = APP_VERSION
    bank_id: str = "intelliresponse-demo"
    hindsight_url: str | None = None
    hindsight_api_key: str | None = None
    groq_api_key: str | None = None
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_models: tuple[str, ...] = ("openai/gpt-oss-120b", "qwen/qwen3-32b")
    otx_api_key: str | None = None
    store_path: str | None = field(default=str(ROOT / ".ir_store.json"))
    llm_enabled: bool = True
    live_osint: bool = False
    max_alert_chars: int = 12000
    osint_timeout: int = 5
    demo_seed_count: int = 20
    max_records: int = 5000


def get_settings() -> Settings:
    """Resolve settings from the environment every call (cheap and testable)."""
    load_dotenv()
    models = tuple(
        m.strip()
        for m in os.getenv(
            "GROQ_MODELS", "openai/gpt-oss-120b,qwen/qwen3-32b"
        ).split(",")
        if m.strip()
    )
    return Settings(
        bank_id=os.getenv("HINDSIGHT_BANK", "intelliresponse-demo").strip()
        or "intelliresponse-demo",
        hindsight_url=validated_url(
            (os.getenv("HINDSIGHT_URL") or os.getenv("HINDSIGHT_BASE_URL") or "").strip()
        ),
        hindsight_api_key=(os.getenv("HINDSIGHT_API_KEY") or "").strip() or None,
        groq_api_key=(os.getenv("GROQ_API_KEY") or "").strip() or None,
        groq_base_url=validated_url(
            os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
            "https://api.groq.com/openai/v1",
        ),
        groq_models=models or ("openai/gpt-oss-120b",),
        otx_api_key=(os.getenv("OTX_API_KEY") or "").strip() or None,
        store_path=os.getenv("IR_STORE_PATH", str(ROOT / ".ir_store.json")).strip()
        or None,
        llm_enabled=_as_bool(os.getenv("IR_LLM_ENABLED"), True),
        live_osint=_as_bool(os.getenv("IR_LIVE_OSINT"), False),
        max_alert_chars=max(1000, _as_int(os.getenv("IR_MAX_ALERT_CHARS"), 12000)),
        osint_timeout=max(1, _as_int(os.getenv("IR_OSINT_TIMEOUT"), 5)),
        demo_seed_count=max(0, _as_int(os.getenv("IR_DEMO_SEED_COUNT"), 20)),
        max_records=max(100, min(100_000, _as_int(os.getenv("IR_MAX_RECORDS"), 5000))),
    )
