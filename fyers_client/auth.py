"""Fyers API v3 authentication.

Fyers does not offer a client-credentials (pure machine-to-machine) grant: an
access token can only originate from an interactive login. The practical
server-to-server pattern is therefore two-stage:

  1. One interactive login  -> auth_code -> access_token + refresh_token.
  2. Unattended renewal     -> refresh_token + appIdHash + PIN -> access_token,
     repeatable without a browser until the refresh token itself expires.

Both tokens are JWTs, so their real expiry is read from the `exp` claim rather
than assumed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from fyers_client.config import (
    TOKEN_CACHE_PATH,
    Credentials,
    MissingCredentialsError,
    load_credentials,
)

API_BASE = "https://api-t1.fyers.in/api/v3"
AUTHCODE_URL = f"{API_BASE}/generate-authcode"
VALIDATE_AUTHCODE_URL = f"{API_BASE}/validate-authcode"
VALIDATE_REFRESH_URL = f"{API_BASE}/validate-refresh-token"

# Renew slightly before real expiry so a long-running job never races the clock.
EXPIRY_SKEW_SECONDS = 120


class AuthError(RuntimeError):
    """Raised when Fyers rejects an authentication request."""


def app_id_hash(client_id: str, secret_key: str) -> str:
    """SHA-256 of "client_id:secret_key" -- the appIdHash Fyers expects."""
    return hashlib.sha256(f"{client_id}:{secret_key}".encode()).hexdigest()


def jwt_expiry(token: str) -> datetime | None:
    """Read the `exp` claim from a JWT without verifying its signature.

    Returns None for anything that is not a readable JWT, so callers fall back
    to attempting the request rather than refusing to try.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)  # restore base64 padding
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        return None
    return datetime.fromtimestamp(exp, tz=timezone.utc)


def _is_live(token: str) -> bool:
    if not token:
        return False
    expiry = jwt_expiry(token)
    if expiry is None:
        return True  # not introspectable; let the API be the judge
    return expiry.timestamp() - EXPIRY_SKEW_SECONDS > time.time()


@dataclass
class TokenSet:
    access_token: str = ""
    refresh_token: str = ""

    @property
    def access_expiry(self) -> datetime | None:
        return jwt_expiry(self.access_token)

    @property
    def refresh_expiry(self) -> datetime | None:
        return jwt_expiry(self.refresh_token)

    def to_dict(self) -> dict[str, str]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
        }


class FyersAuth:
    """Owns the token lifecycle for one Fyers app."""

    def __init__(
        self,
        credentials: Credentials | None = None,
        cache_path: Path | None = None,
    ) -> None:
        self.credentials = credentials or load_credentials()
        self.cache_path = cache_path or TOKEN_CACHE_PATH
        self._tokens = self._read_cache()
        if not self._tokens.access_token and self.credentials.access_token:
            self._tokens.access_token = self.credentials.access_token

    # ---------------------------------------------------------------- cache

    def _read_cache(self) -> TokenSet:
        if not self.cache_path.exists():
            return TokenSet()
        try:
            raw = json.loads(self.cache_path.read_text())
        except (OSError, ValueError):
            return TokenSet()
        return TokenSet(
            access_token=raw.get("access_token", ""),
            refresh_token=raw.get("refresh_token", ""),
        )

    def _write_cache(self) -> None:
        self.cache_path.write_text(json.dumps(self._tokens.to_dict(), indent=2))
        self.cache_path.chmod(0o600)  # tokens are bearer credentials

    # ----------------------------------------------------------- stage one

    def login_url(self, state: str = "fyers_client") -> str:
        """URL the account holder opens in a browser to produce an auth_code."""
        self.credentials.require("client_id", "redirect_uri")
        from urllib.parse import urlencode

        params = {
            "client_id": self.credentials.client_id,
            "redirect_uri": self.credentials.redirect_uri,
            "response_type": "code",
            "state": state,
        }
        return f"{AUTHCODE_URL}?{urlencode(params)}"

    def exchange_auth_code(self, auth_code: str) -> TokenSet:
        """Trade an auth_code for an access token and a refresh token."""
        self.credentials.require("client_id", "secret_key")
        payload = {
            "grant_type": "authorization_code",
            "appIdHash": app_id_hash(
                self.credentials.client_id, self.credentials.secret_key
            ),
            "code": auth_code,
        }
        body = self._post(VALIDATE_AUTHCODE_URL, payload)
        self._tokens = TokenSet(
            access_token=body.get("access_token", ""),
            refresh_token=body.get("refresh_token", ""),
        )
        if not self._tokens.access_token:
            raise AuthError(f"No access_token in Fyers response: {body}")
        self._write_cache()
        return self._tokens

    # ----------------------------------------------------------- stage two

    def refresh(self, pin: str) -> TokenSet:
        """Mint a fresh access token from the stored refresh token.

        This is the unattended path: no browser, no auth_code. It works until
        the refresh token expires, at which point a new interactive login is
        unavoidable.
        """
        self.credentials.require("client_id", "secret_key")
        if not self._tokens.refresh_token:
            raise AuthError(
                "No refresh token stored. Run the interactive login once "
                "(`python -m fyers_client.cli login`) to obtain one."
            )
        if not _is_live(self._tokens.refresh_token):
            raise AuthError(
                "Stored refresh token has expired. Fyers refresh tokens are "
                "short-lived (~15 days); run the interactive login again."
            )
        if not pin:
            raise MissingCredentialsError(
                "A PIN is required to refresh. Set FYERS_PIN or pass --pin."
            )
        payload = {
            "grant_type": "refresh_token",
            "appIdHash": app_id_hash(
                self.credentials.client_id, self.credentials.secret_key
            ),
            "refresh_token": self._tokens.refresh_token,
            "pin": pin,
        }
        body = self._post(VALIDATE_REFRESH_URL, payload)
        access = body.get("access_token", "")
        if not access:
            raise AuthError(f"No access_token in Fyers refresh response: {body}")
        self._tokens.access_token = access
        # Fyers returns a rotated refresh token on some plans; keep it if sent.
        if body.get("refresh_token"):
            self._tokens.refresh_token = body["refresh_token"]
        self._write_cache()
        return self._tokens

    # -------------------------------------------------------------- public

    def access_token(self, pin: str = "", allow_refresh: bool = True) -> str:
        """Return a usable access token, refreshing it when possible.

        Call this at the top of every scheduled job; it is a no-op while the
        cached token is still valid.
        """
        if _is_live(self._tokens.access_token):
            return self._tokens.access_token
        if allow_refresh and self._tokens.refresh_token:
            return self.refresh(pin).access_token
        raise AuthError(
            "No valid access token available. Run "
            "`python -m fyers_client.cli login` to authenticate."
        )

    def status(self) -> dict[str, Any]:
        """Human-readable view of the cached tokens, for diagnostics."""

        def describe(token: str, expiry: datetime | None) -> dict[str, Any]:
            return {
                "present": bool(token),
                "expires_at_utc": expiry.isoformat() if expiry else None,
                "valid": _is_live(token),
            }

        return {
            "cache_path": str(self.cache_path),
            "access_token": describe(
                self._tokens.access_token, self._tokens.access_expiry
            ),
            "refresh_token": describe(
                self._tokens.refresh_token, self._tokens.refresh_expiry
            ),
        }

    # ------------------------------------------------------------ internal

    @staticmethod
    def _post(url: str, payload: dict[str, str]) -> dict[str, Any]:
        try:
            response = requests.post(url, json=payload, timeout=30)
        except requests.RequestException as exc:
            raise AuthError(f"Could not reach Fyers at {url}: {exc}") from exc
        try:
            body = response.json()
        except ValueError:
            raise AuthError(
                f"Fyers returned non-JSON ({response.status_code}): "
                f"{response.text[:300]}"
            ) from None
        if body.get("s") != "ok":
            raise AuthError(
                f"Fyers rejected the request ({body.get('code')}): "
                f"{body.get('message') or body}"
            )
        return body
