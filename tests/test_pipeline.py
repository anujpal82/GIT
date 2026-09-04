"""Offline verification of the Fyers client.

Every Fyers HTTP call is replaced with a recorded-shape fake, so the auth
lifecycle, range chunking and pandas conversion are exercised end to end
without touching the network or needing live credentials.
"""

from __future__ import annotations

import base64
import json
import sys
import time
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd

from fyers_client import auth as auth_mod
from fyers_client.auth import AuthError, FyersAuth, app_id_hash, jwt_expiry
from fyers_client.config import Credentials
from fyers_client.historical import (
    HistoricalClient,
    HistoryError,
    candles_to_dataframe,
    date_chunks,
)


def make_jwt(expires_in_seconds: int) -> str:
    """Craft an unsigned JWT whose exp claim is `expires_in_seconds` away."""
    claims = {"exp": int(time.time()) + expires_in_seconds}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


# 2025-06-02 09:15 IST and 09:16 IST, as the UTC epochs Fyers actually sends.
CANDLES = [
    [1748835900, 100.0, 105.5, 99.5, 104.0, 15000],
    [1748835960, 104.0, 106.0, 103.5, 105.0, 12000],
]


class FakeModel:
    """Stands in for fyersModel.FyersModel."""

    def __init__(self, responses=None, profile=None):
        self.responses = list(responses or [])
        self.profile_response = profile or {"s": "ok", "data": {"name": "Test User"}}
        self.calls = []

    def history(self, data=None):
        self.calls.append(data)
        if self.responses:
            return self.responses.pop(0)
        return {"s": "ok", "candles": []}

    def get_profile(self):
        return self.profile_response


def make_client(model: FakeModel) -> HistoricalClient:
    creds = Credentials(
        client_id="TEST1234-100",
        secret_key="secret",
        redirect_uri="https://127.0.0.1:8080/",
        access_token=make_jwt(3600),
    )
    fyers_auth = FyersAuth(creds, cache_path=Path("/nonexistent/token.json"))
    client = HistoricalClient(auth=fyers_auth, retry_backoff=0, pause_between_chunks=0)
    client._model = model
    return client


class TestAppIdHash(unittest.TestCase):
    def test_matches_documented_formula(self):
        import hashlib

        expected = hashlib.sha256(b"TEST1234-100:secret").hexdigest()
        self.assertEqual(app_id_hash("TEST1234-100", "secret"), expected)


class TestJwtExpiry(unittest.TestCase):
    def test_reads_exp_claim(self):
        expiry = jwt_expiry(make_jwt(3600))
        self.assertIsNotNone(expiry)
        delta = expiry - datetime.now(timezone.utc)
        self.assertAlmostEqual(delta.total_seconds(), 3600, delta=5)

    def test_returns_none_for_non_jwt(self):
        for value in ("", "opaque-token", "a.b", "a.!!!.c"):
            self.assertIsNone(jwt_expiry(value), value)


class TestDateChunks(unittest.TestCase):
    def test_single_window_when_range_fits(self):
        chunks = list(date_chunks(date(2025, 1, 1), date(2025, 3, 1), 366))
        self.assertEqual(chunks, [(date(2025, 1, 1), date(2025, 3, 1))])

    def test_windows_are_contiguous_and_within_cap(self):
        start, end, cap = date(2023, 1, 1), date(2026, 1, 1), 100
        chunks = list(date_chunks(start, end, cap))
        self.assertEqual(chunks[0][0], start)
        self.assertEqual(chunks[-1][1], end)
        for (_, prev_end), (next_start, _) in zip(chunks, chunks[1:]):
            self.assertEqual(next_start - prev_end, timedelta(days=1))
        for window_start, window_end in chunks:
            self.assertLessEqual((window_end - window_start).days + 1, cap)

    def test_rejects_inverted_range(self):
        with self.assertRaises(ValueError):
            list(date_chunks(date(2025, 2, 1), date(2025, 1, 1), 100))


class TestCandlesToDataFrame(unittest.TestCase):
    def test_shape_index_and_dtypes(self):
        frame = candles_to_dataframe(CANDLES)
        self.assertEqual(list(frame.columns), ["open", "high", "low", "close", "volume"])
        self.assertEqual(frame.index.name, "timestamp")
        self.assertEqual(str(frame.index.tz), "Asia/Kolkata")
        self.assertTrue(all(str(frame[c].dtype) == "float64" for c in frame.columns))
        self.assertEqual(frame["close"].iloc[0], 104.0)

    def test_epoch_converts_to_ist_wall_clock(self):
        frame = candles_to_dataframe(CANDLES)
        first = frame.index[0]
        self.assertEqual((first.hour, first.minute), (9, 15))
        self.assertEqual(first.date(), date(2025, 6, 2))

    def test_sorts_and_drops_duplicate_timestamps(self):
        scrambled = [CANDLES[1], CANDLES[0], CANDLES[0]]
        frame = candles_to_dataframe(scrambled)
        self.assertEqual(len(frame), 2)
        self.assertTrue(frame.index.is_monotonic_increasing)

    def test_empty_input_gives_typed_empty_frame(self):
        frame = candles_to_dataframe([])
        self.assertTrue(frame.empty)
        self.assertEqual(list(frame.columns), ["open", "high", "low", "close", "volume"])
        self.assertEqual(str(frame.index.tz), "Asia/Kolkata")


class TestHistoricalFetch(unittest.TestCase):
    def test_stitches_multiple_chunks(self):
        model = FakeModel([
            {"s": "ok", "candles": [CANDLES[0]]},
            {"s": "ok", "candles": [CANDLES[1]]},
        ])
        client = make_client(model)
        frame = client.fetch(
            "NSE:SBIN-EQ", resolution="5", start="2025-01-01", end="2025-06-30"
        )
        self.assertEqual(len(model.calls), 2)
        self.assertEqual(len(frame), 2)
        self.assertEqual(frame.attrs["requests_made"], 2)
        self.assertEqual(model.calls[0]["resolution"], "5")
        self.assertEqual(model.calls[0]["date_format"], "1")
        self.assertEqual(model.calls[0]["range_from"], "2025-01-01")

    def test_no_data_is_not_an_error(self):
        client = make_client(FakeModel([{"s": "no_data"}]))
        frame = client.fetch("NSE:SBIN-EQ", start="2025-01-01", end="2025-01-10")
        self.assertTrue(frame.empty)

    def test_retries_then_raises_with_broker_message(self):
        error = {"s": "error", "code": -300, "message": "invalid symbol"}
        model = FakeModel([error, error, error])
        client = make_client(model)
        with self.assertRaises(HistoryError) as ctx:
            client.fetch("NSE:BOGUS", start="2025-01-01", end="2025-01-10")
        self.assertEqual(len(model.calls), 3)
        self.assertIn("invalid symbol", str(ctx.exception))

    def test_rejects_unknown_resolution(self):
        client = make_client(FakeModel())
        with self.assertRaises(ValueError):
            client.fetch("NSE:SBIN-EQ", resolution="7m", start="2025-01-01")

    def test_check_connection_surfaces_failure(self):
        model = FakeModel(profile={"s": "error", "code": -16, "message": "bad token"})
        with self.assertRaises(HistoryError) as ctx:
            make_client(model).check_connection()
        self.assertIn("bad token", str(ctx.exception))


class TestRefreshFlow(unittest.TestCase):
    def setUp(self):
        self.cache = Path(__file__).parent / "_tmp_token.json"
        self.creds = Credentials("TEST1234-100", "secret", "https://127.0.0.1:8080/")

    def tearDown(self):
        self.cache.unlink(missing_ok=True)

    def _auth_with(self, access: str, refresh: str) -> FyersAuth:
        self.cache.write_text(
            json.dumps({"access_token": access, "refresh_token": refresh})
        )
        return FyersAuth(self.creds, cache_path=self.cache)

    def test_valid_token_is_reused_without_network(self):
        token = make_jwt(3600)
        fyers_auth = self._auth_with(token, make_jwt(86400))
        with mock.patch.object(auth_mod.requests, "post") as post:
            self.assertEqual(fyers_auth.access_token("1234"), token)
        post.assert_not_called()

    def test_expired_access_token_triggers_refresh(self):
        fyers_auth = self._auth_with(make_jwt(-10), make_jwt(86400))
        fresh = make_jwt(3600)
        response = mock.Mock()
        response.json.return_value = {"s": "ok", "code": 200, "access_token": fresh}
        with mock.patch.object(auth_mod.requests, "post", return_value=response) as post:
            self.assertEqual(fyers_auth.access_token("1234"), fresh)
        sent = post.call_args.kwargs["json"]
        self.assertEqual(sent["grant_type"], "refresh_token")
        self.assertEqual(sent["pin"], "1234")
        self.assertEqual(sent["appIdHash"], app_id_hash("TEST1234-100", "secret"))
        # The renewed token must survive for the next process.
        self.assertEqual(json.loads(self.cache.read_text())["access_token"], fresh)

    def test_expired_refresh_token_asks_for_interactive_login(self):
        fyers_auth = self._auth_with(make_jwt(-10), make_jwt(-10))
        with self.assertRaises(AuthError) as ctx:
            fyers_auth.access_token("1234")
        self.assertIn("interactive login", str(ctx.exception))

    def test_broker_rejection_is_reported(self):
        fyers_auth = self._auth_with(make_jwt(-10), make_jwt(86400))
        response = mock.Mock()
        response.json.return_value = {"s": "error", "code": -413, "message": "bad pin"}
        with mock.patch.object(auth_mod.requests, "post", return_value=response):
            with self.assertRaises(AuthError) as ctx:
                fyers_auth.access_token("0000")
        self.assertIn("bad pin", str(ctx.exception))

    def test_login_url_carries_app_and_redirect(self):
        fyers_auth = FyersAuth(self.creds, cache_path=self.cache)
        url = fyers_auth.login_url()
        self.assertIn("generate-authcode", url)
        self.assertIn("client_id=TEST1234-100", url)
        self.assertIn("response_type=code", url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
