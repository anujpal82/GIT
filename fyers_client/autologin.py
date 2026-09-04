"""Unattended TOTP login: Fyers ID + PIN + TOTP secret -> auth_code.

WARNING -- this uses Fyers' *internal* login endpoints, the ones the web app
calls. They are not part of the published API, carry no compatibility promise,
and have moved hosts before. Every URL is overridable by environment variable
(see STEP_ENV_VARS) so a change on Fyers' side is a config edit, not a code
change.

The flow mirrors what a browser does:

    1. send_login_otp   fy_id                     -> request_key
    2. verify_otp       request_key + TOTP        -> request_key
    3. verify_pin       request_key + PIN         -> session token
    4. token            session token + app_id    -> redirect URL with auth_code

The auth_code that falls out is then exchanged through the *documented*
/validate-authcode endpoint, exactly as the interactive flow does.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests

from fyers_client.config import API_BASE, Credentials
from fyers_client.totp import fresh_totp

REQUEST_TIMEOUT = 30

STEP_ENV_VARS = {
    "send_login_otp": "FYERS_SEND_OTP_URL",
    "verify_otp": "FYERS_VERIFY_OTP_URL",
    "verify_pin": "FYERS_VERIFY_PIN_URL",
    "token": "FYERS_TOKEN_URL",
}


def login_urls() -> dict[str, str]:
    """Resolve the login endpoints, honouring per-step environment overrides.

    Read at call time rather than import time so redirecting an endpoint takes
    effect without reimporting the module.
    """
    base = os.getenv("FYERS_LOGIN_BASE", API_BASE).rstrip("/")
    return {
        step: os.getenv(env_var, f"{base}/{step}")
        for step, env_var in STEP_ENV_VARS.items()
    }


class AutoLoginError(RuntimeError):
    """Raised when a step of the headless login fails.

    Carries the step name so a failure points at one request rather than the
    whole flow.
    """

    def __init__(self, step: str, message: str) -> None:
        super().__init__(f"[{step}] {message}")
        self.step = step


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


@dataclass
class AutoLogin:
    """Drives the four-step headless login."""

    credentials: Credentials
    session: Any = None
    totp_min_validity: float = 5.0
    urls: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.session is None:
            self.session = requests.Session()
        if self.urls is None:
            self.urls = login_urls()

    # ------------------------------------------------------------- helpers

    def _post(
        self, step: str, url: str, payload: dict, headers: dict | None = None
    ) -> dict:
        try:
            response = self.session.post(
                url, json=payload, headers=headers or {}, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as exc:
            raise AutoLoginError(step, f"could not reach {url}: {exc}") from exc
        try:
            body = response.json()
        except ValueError:
            raise AutoLoginError(
                step,
                f"expected JSON from {url}, got HTTP {response.status_code}: "
                f"{response.text[:200]}",
            ) from None
        if response.status_code >= 400 or body.get("s") == "error":
            raise AutoLoginError(
                step,
                f"HTTP {response.status_code} -- "
                f"{body.get('message') or body.get('msg') or body}",
            )
        return body

    @staticmethod
    def _require(step: str, body: dict, key: str) -> str:
        value = body.get(key) or body.get("data", {}).get(key)
        if not value:
            raise AutoLoginError(
                step, f"response had no {key!r}; got keys {sorted(body)}"
            )
        return value

    # --------------------------------------------------------------- steps

    def send_login_otp(self) -> str:
        """Step 1: announce the Fyers ID, receive a request key."""
        body = self._post(
            "send_login_otp",
            self.urls["send_login_otp"],
            {"fy_id": _b64(self.credentials.fy_id), "app_id": "2"},
        )
        return self._require("send_login_otp", body, "request_key")

    def verify_otp(self, request_key: str) -> str:
        """Step 2: answer the OTP challenge with a freshly generated TOTP."""
        code = fresh_totp(
            self.credentials.totp_secret, min_validity=self.totp_min_validity
        )
        body = self._post(
            "verify_otp",
            self.urls["verify_otp"],
            {"request_key": request_key, "otp": code},
        )
        return self._require("verify_otp", body, "request_key")

    def verify_pin(self, request_key: str) -> str:
        """Step 3: supply the account PIN, receive a short-lived session token."""
        body = self._post(
            "verify_pin",
            self.urls["verify_pin"],
            {
                "request_key": request_key,
                "identity_type": "pin",
                "identifier": _b64(self.credentials.pin),
            },
        )
        return self._require("verify_pin", body, "access_token")

    def fetch_auth_code(self, session_token: str) -> str:
        """Step 4: trade the session token for a redirect URL bearing auth_code."""
        body = self._post(
            "token",
            self.urls["token"],
            {
                "fyers_id": self.credentials.fy_id,
                "app_id": self.credentials.app_id,
                "redirect_uri": self.credentials.redirect_uri,
                "appType": self.credentials.app_type,
                "code_challenge": "",
                "state": "auto_login",
                "scope": "",
                "nonce": "",
                "response_type": "code",
                "create_cookie": True,
            },
            headers={"Authorization": f"Bearer {session_token}"},
        )
        url = body.get("Url") or body.get("url") or ""
        if not url:
            raise AutoLoginError(
                "token", f"response had no redirect URL; got keys {sorted(body)}"
            )
        codes = parse_qs(urlparse(url).query).get("auth_code", [])
        if not codes:
            raise AutoLoginError("token", f"no auth_code in redirect URL: {url[:200]}")
        return codes[0]

    # -------------------------------------------------------------- public

    def auth_code(self) -> str:
        """Run all four steps and return an auth_code."""
        if not self.credentials.can_auto_login:
            raise AutoLoginError(
                "preflight",
                "auto-login needs FYERS_ID, FYERS_PIN and FYERS_TOTP_SECRET "
                "alongside the app credentials.",
            )
        request_key = self.send_login_otp()
        request_key = self.verify_otp(request_key)
        session_token = self.verify_pin(request_key)
        return self.fetch_auth_code(session_token)
