"""The headless TOTP login, verified against a faked Fyers transport."""

from __future__ import annotations

import base64
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fyers_client.autologin import (
    STEP_ENV_VARS,
    AutoLogin,
    AutoLoginError,
    login_urls,
)
from fyers_client.config import Credentials

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

CREDS = Credentials(
    client_id="TEST1234-100",
    secret_key="secret",
    redirect_uri="https://127.0.0.1:8080/",
    fy_id="XA12345",
    pin="1234",
    totp_secret=RFC_SECRET,
)


class FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code
        self.text = str(body)

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeSession:
    """Records posts and replays queued responses in order."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.posts = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.posts.append({"url": url, "json": json, "headers": headers or {}})
        return self.responses.pop(0)


def happy_path_session():
    return FakeSession([
        FakeResponse({"s": "ok", "request_key": "rk-otp"}),
        FakeResponse({"s": "ok", "request_key": "rk-pin"}),
        FakeResponse({"s": "ok", "data": {"access_token": "session-token"}}),
        FakeResponse(
            {"s": "ok", "Url": "https://127.0.0.1:8080/?auth_code=AUTH123&state=x"}
        ),
    ])


class TestHappyPath(unittest.TestCase):
    def setUp(self):
        self.session = happy_path_session()
        self.login = AutoLogin(CREDS, session=self.session, totp_min_validity=0)

    def test_returns_auth_code_from_redirect_url(self):
        self.assertEqual(self.login.auth_code(), "AUTH123")

    def test_makes_exactly_four_requests_in_order(self):
        self.login.auth_code()
        paths = [p["url"].rsplit("/", 1)[-1] for p in self.session.posts]
        self.assertEqual(paths, ["send_login_otp", "verify_otp", "verify_pin", "token"])

    def test_identifiers_are_base64_encoded(self):
        self.login.auth_code()
        sent_id = self.session.posts[0]["json"]["fy_id"]
        sent_pin = self.session.posts[2]["json"]["identifier"]
        self.assertEqual(base64.b64decode(sent_id).decode(), "XA12345")
        self.assertEqual(base64.b64decode(sent_pin).decode(), "1234")

    def test_otp_is_a_six_digit_code(self):
        self.login.auth_code()
        otp = self.session.posts[1]["json"]["otp"]
        self.assertRegex(otp, r"^\d{6}$")

    def test_request_key_is_threaded_between_steps(self):
        self.login.auth_code()
        self.assertEqual(self.session.posts[1]["json"]["request_key"], "rk-otp")
        self.assertEqual(self.session.posts[2]["json"]["request_key"], "rk-pin")

    def test_token_step_splits_client_id_and_bears_session_token(self):
        self.login.auth_code()
        final = self.session.posts[3]
        self.assertEqual(final["json"]["app_id"], "TEST1234")
        self.assertEqual(final["json"]["appType"], "100")
        self.assertEqual(final["headers"]["Authorization"], "Bearer session-token")


class TestFailures(unittest.TestCase):
    def _login(self, responses):
        return AutoLogin(CREDS, session=FakeSession(responses), totp_min_validity=0)

    def test_each_step_is_named_in_its_error(self):
        cases = {
            "send_login_otp": [FakeResponse({"s": "error", "message": "bad id"})],
            "verify_otp": [
                FakeResponse({"s": "ok", "request_key": "rk"}),
                FakeResponse({"s": "error", "message": "invalid otp"}),
            ],
            "verify_pin": [
                FakeResponse({"s": "ok", "request_key": "rk"}),
                FakeResponse({"s": "ok", "request_key": "rk2"}),
                FakeResponse({"s": "error", "message": "wrong pin"}),
            ],
        }
        for step, responses in cases.items():
            with self.subTest(step=step):
                with self.assertRaises(AutoLoginError) as ctx:
                    self._login(responses).auth_code()
                self.assertEqual(ctx.exception.step, step)

    def test_missing_auth_code_in_redirect_is_reported(self):
        responses = happy_path_session().responses[:3] + [
            FakeResponse({"s": "ok", "Url": "https://127.0.0.1:8080/?error=denied"})
        ]
        with self.assertRaises(AutoLoginError) as ctx:
            self._login(responses).auth_code()
        self.assertEqual(ctx.exception.step, "token")
        self.assertIn("no auth_code", str(ctx.exception))

    def test_html_error_page_does_not_crash_with_a_json_error(self):
        with self.assertRaises(AutoLoginError) as ctx:
            self._login([FakeResponse(ValueError("no json"), 502)]).auth_code()
        self.assertIn("expected JSON", str(ctx.exception))

    def test_missing_key_lists_what_came_back(self):
        with self.assertRaises(AutoLoginError) as ctx:
            self._login([FakeResponse({"s": "ok", "unexpected": 1})]).auth_code()
        self.assertIn("request_key", str(ctx.exception))

    def test_incomplete_credentials_fail_before_any_request(self):
        partial = Credentials("TEST1234-100", "secret", "https://127.0.0.1:8080/")
        session = FakeSession([])
        with self.assertRaises(AutoLoginError) as ctx:
            AutoLogin(partial, session=session).auth_code()
        self.assertEqual(ctx.exception.step, "preflight")
        self.assertEqual(session.posts, [])


class TestEndpointOverrides(unittest.TestCase):
    """Endpoints must be redirectable, since these are undocumented URLs."""

    def test_defaults_hang_off_the_api_base(self):
        urls = login_urls()
        self.assertEqual(set(urls), set(STEP_ENV_VARS))
        for step, url in urls.items():
            self.assertTrue(url.endswith(f"/{step}"), url)

    def test_base_override_moves_every_endpoint(self):
        with mock.patch.dict(os.environ, {"FYERS_LOGIN_BASE": "https://example.test/v9"}):
            urls = login_urls()
        self.assertEqual(urls["send_login_otp"], "https://example.test/v9/send_login_otp")
        self.assertEqual(urls["token"], "https://example.test/v9/token")

    def test_single_step_can_be_redirected(self):
        with mock.patch.dict(os.environ, {"FYERS_VERIFY_OTP_URL": "https://other.test/otp"}):
            urls = login_urls()
        self.assertEqual(urls["verify_otp"], "https://other.test/otp")
        self.assertTrue(urls["token"].endswith("/token"))

    def test_login_uses_the_injected_url_map(self):
        session = happy_path_session()
        login = AutoLogin(
            CREDS,
            session=session,
            totp_min_validity=0,
            urls={s: f"https://custom.test/{s}" for s in STEP_ENV_VARS},
        )
        login.auth_code()
        self.assertTrue(
            all(p["url"].startswith("https://custom.test/") for p in session.posts)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
