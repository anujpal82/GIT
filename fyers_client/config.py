"""Credential loading and shared constants."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
TOKEN_CACHE_PATH = PROJECT_ROOT / ".fyers_token.json"

# Exchange timezone for every Indian market timestamp Fyers returns.
IST = "Asia/Kolkata"

# Maximum span Fyers accepts in a single /data/history request. Longer ranges
# have to be split into consecutive chunks and stitched back together.
MAX_DAYS_DAILY = 366
MAX_DAYS_INTRADAY = 100

# Resolutions the history endpoint accepts, mapped to their per-request cap.
DAILY_RESOLUTIONS = {"D", "1D", "Day"}
INTRADAY_RESOLUTIONS = {
    "1", "2", "3", "5", "10", "15", "20", "30", "45", "60", "120", "240",
}


class MissingCredentialsError(RuntimeError):
    """Raised when a required credential is absent from the environment."""


@dataclass(frozen=True)
class Credentials:
    client_id: str
    secret_key: str
    redirect_uri: str
    access_token: str = ""

    def require(self, *fields: str) -> None:
        missing = [f for f in fields if not getattr(self, f)]
        if missing:
            names = ", ".join(f"FYERS_{f.upper()}" for f in missing)
            raise MissingCredentialsError(
                f"Missing required credential(s): {names}. "
                f"Copy .env.example to .env and fill them in."
            )


def load_credentials(env_path: Path | None = None) -> Credentials:
    """Read credentials from .env (if present) and the process environment."""
    path = env_path or ENV_PATH
    if path.exists():
        load_dotenv(path, override=False)
    return Credentials(
        client_id=os.getenv("FYERS_CLIENT_ID", "").strip(),
        secret_key=os.getenv("FYERS_SECRET_KEY", "").strip(),
        redirect_uri=os.getenv("FYERS_REDIRECT_URI", "").strip(),
        access_token=os.getenv("FYERS_ACCESS_TOKEN", "").strip(),
    )


def max_days_for(resolution: str) -> int:
    """Per-request day cap for a resolution."""
    if resolution in DAILY_RESOLUTIONS:
        return MAX_DAYS_DAILY
    if resolution in INTRADAY_RESOLUTIONS:
        return MAX_DAYS_INTRADAY
    valid = sorted(DAILY_RESOLUTIONS | INTRADAY_RESOLUTIONS)
    raise ValueError(f"Unsupported resolution {resolution!r}. Expected one of: {valid}")
