"""Historical candle retrieval from Fyers API v3, delivered as pandas frames."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Iterator, Sequence

import pandas as pd
from fyers_apiv3 import fyersModel

from fyers_client.auth import FyersAuth
from fyers_client.config import IST, max_days_for

CANDLE_COLUMNS = ["timestamp", "open", "high", "low", "close", "volume"]
OHLCV = ["open", "high", "low", "close", "volume"]


class HistoryError(RuntimeError):
    """Raised when Fyers returns an error for a history request."""


def _as_date(value: str | date | datetime) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return datetime.strptime(value, "%Y-%m-%d").date()


def date_chunks(
    start: date, end: date, max_days: int
) -> Iterator[tuple[date, date]]:
    """Split an inclusive date range into windows Fyers will accept.

    Fyers caps a single /history call at 366 days for daily candles and 100
    days for intraday ones, so anything longer is fetched in consecutive
    windows and stitched back together.
    """
    if start > end:
        raise ValueError(f"start ({start}) is after end ({end})")
    cursor = start
    step = timedelta(days=max_days - 1)
    while cursor <= end:
        window_end = min(cursor + step, end)
        yield cursor, window_end
        cursor = window_end + timedelta(days=1)


def candles_to_dataframe(
    candles: Sequence[Sequence[Any]], tz: str = IST
) -> pd.DataFrame:
    """Turn raw Fyers candles into a tz-aware, time-indexed OHLCV frame.

    Fyers returns rows of [epoch_seconds, open, high, low, close, volume] with
    the epoch in UTC; the index is converted to exchange-local time so daily
    candles land on the correct trading date.
    """
    frame = pd.DataFrame(list(candles), columns=CANDLE_COLUMNS)
    if frame.empty:
        empty = pd.DataFrame(columns=OHLCV)
        empty.index = pd.DatetimeIndex([], tz=tz, name="timestamp")
        return empty.astype({c: "float64" for c in OHLCV})

    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"], unit="s", utc=True
    ).dt.tz_convert(tz)
    frame[OHLCV] = frame[OHLCV].astype("float64")
    frame = frame.set_index("timestamp").sort_index()
    # Chunk boundaries can repeat a candle; keep one row per timestamp.
    return frame[~frame.index.duplicated(keep="last")]


@dataclass
class HistoricalClient:
    """Fetches candles and hands back pandas frames."""

    auth: FyersAuth
    pin: str = ""
    max_retries: int = 3
    retry_backoff: float = 2.0
    pause_between_chunks: float = 0.35  # stay under the ~10 req/s data limit
    _model: Any = None

    def model(self) -> Any:
        """Build (once) an authenticated FyersModel."""
        if self._model is None:
            self._model = fyersModel.FyersModel(
                client_id=self.auth.credentials.client_id,
                token=self.auth.access_token(self.pin),
                is_async=False,
                log_path="",
            )
        return self._model

    def check_connection(self) -> dict[str, Any]:
        """Call /profile as a cheap end-to-end credential check."""
        response = self.model().get_profile()
        if response.get("s") != "ok":
            raise HistoryError(
                f"Profile check failed ({response.get('code')}): "
                f"{response.get('message') or response}"
            )
        return response.get("data", {})

    def _fetch_window(
        self, symbol: str, resolution: str, start: date, end: date, cont_flag: str
    ) -> list[list[Any]]:
        payload = {
            "symbol": symbol,
            "resolution": resolution,
            "date_format": "1",
            "range_from": start.isoformat(),
            "range_to": end.isoformat(),
            "cont_flag": cont_flag,
        }
        last_error: str = ""
        for attempt in range(1, self.max_retries + 1):
            response = self.model().history(data=payload)
            status = response.get("s")
            if status == "ok":
                return response.get("candles", []) or []
            if status == "no_data":
                return []
            last_error = (
                f"{response.get('code')}: {response.get('message') or response}"
            )
            if attempt < self.max_retries:
                time.sleep(self.retry_backoff ** attempt)
        raise HistoryError(
            f"history failed for {symbol} {start}..{end} after "
            f"{self.max_retries} attempts -- {last_error}"
        )

    def fetch(
        self,
        symbol: str,
        resolution: str = "D",
        start: str | date | datetime = "",
        end: str | date | datetime = "",
        cont_flag: str = "1",
        tz: str = IST,
    ) -> pd.DataFrame:
        """Fetch an inclusive date range as a single OHLCV DataFrame.

        Ranges longer than the per-request cap are split automatically.
        """
        end_date = _as_date(end) if end else date.today()
        start_date = _as_date(start) if start else end_date - timedelta(days=30)
        cap = max_days_for(resolution)

        candles: list[list[Any]] = []
        windows = list(date_chunks(start_date, end_date, cap))
        for index, (window_start, window_end) in enumerate(windows):
            candles.extend(
                self._fetch_window(
                    symbol, resolution, window_start, window_end, cont_flag
                )
            )
            if index < len(windows) - 1 and self.pause_between_chunks:
                time.sleep(self.pause_between_chunks)

        frame = candles_to_dataframe(candles, tz=tz)
        frame.attrs.update(
            {
                "symbol": symbol,
                "resolution": resolution,
                "requested_from": start_date.isoformat(),
                "requested_to": end_date.isoformat(),
                "requests_made": len(windows),
            }
        )
        return frame
