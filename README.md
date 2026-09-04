# Fyers API v3 — historical data client

Connects to [Fyers](https://myapi.fyers.in/) API v3, pulls historical candles,
and returns them as clean pandas DataFrames.

## Can I log in server-to-server with just client_id + secret?

**No — Fyers has no client-credentials grant.** The secret alone cannot mint an
access token. It is only used to compute `appIdHash = sha256("client_id:secret_key")`,
which authenticates the *second* leg of the flow. The first leg requires an
interactive login (Fyers ID, TOTP, PIN) because the token authorises a real
trading account under SEBI 2FA rules. The official `fyers-apiv3` SDK has no
refresh or machine-to-machine method either.

What you *can* have is **one interactive login, then unattended renewal**:

```
  browser login ──▶ auth_code ──▶ access_token + refresh_token     (once)
                                        │
                                        ▼
       refresh_token + appIdHash + PIN ──▶ new access_token   (no browser,
                                                              repeatable)
```

The refresh token lasts roughly 15 days, so a scheduled job renews itself
without human involvement until then, at which point one browser login is
unavoidable. `FyersAuth.access_token()` implements exactly this: it returns the
cached token while valid, silently refreshes when expired, and only raises when
a new interactive login is genuinely required. Both tokens are JWTs, so expiry
is read from the `exp` claim rather than assumed.

Some people automate the browser leg by scripting the TOTP login. It works, but
it is fragile and puts your 2FA seed on the server — check Fyers' terms before
going that route. This repo does not do it.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env      # then fill in client_id, secret_key, redirect_uri
python scripts/verify_setup.py
```

`verify_setup.py` reports packages, credentials, token validity, API
reachability, and runs the candle→DataFrame conversion on a sample payload, so
the pandas half is verifiable before any credential exists.

The redirect URI in `.env` must match the one registered on the Fyers app
dashboard character for character, or `/generate-authcode` rejects the request.

## Usage

```bash
python -m fyers_client.cli login      # once: prints the URL, takes the auth_code
python -m fyers_client.cli check      # verifies the token against /profile
python -m fyers_client.cli refresh    # unattended renewal (needs FYERS_PIN)
python -m fyers_client.cli status     # what is in the token cache

python -m fyers_client.cli history \
    --symbol NSE:SBIN-EQ --resolution D \
    --start 2023-01-01 --end 2025-12-31 --out data/sbin.csv
```

From Python:

```python
from fyers_client import FyersAuth, HistoricalClient

client = HistoricalClient(auth=FyersAuth(), pin="1234")
df = client.fetch("NSE:SBIN-EQ", resolution="5",
                  start="2025-01-01", end="2025-06-30")

df.head()
#                             open    high     low   close     volume
# timestamp
# 2025-01-01 09:15:00+05:30  812.5  818.90  809.15  816.40   948233.0

df["close"].resample("D").ohlc()          # index is tz-aware, so this is correct
```

### What the DataFrame guarantees

- **Index** — `timestamp`, tz-aware in `Asia/Kolkata`. Fyers sends UTC epochs;
  converting matters, because a daily candle at `2025-06-02T18:30:00Z` belongs
  to trading day **June 3**, not June 2. Getting this wrong silently shifts
  every daily bar by one day.
- **Columns** — `open, high, low, close, volume`, all `float64`.
- **Sorted and de-duplicated** — chunk boundaries can repeat a candle; only one
  row per timestamp survives.
- **`df.attrs`** — carries `symbol`, `resolution`, the requested range, and
  `requests_made`.

### Long ranges are chunked automatically

Fyers caps one `/history` call at **366 days** for daily candles and **100 days**
for intraday. `fetch()` splits longer ranges into contiguous windows, paces them
under the rate limit, and stitches the result — so a five-year 5-minute pull is
one call in your code.

## Tests

```bash
python -m unittest discover -s tests -v
```

20 tests, no network and no credentials required: every Fyers HTTP call is
replaced with a fake of the documented response shape. They cover the appIdHash
formula, JWT expiry parsing, the refresh lifecycle (reuse / renew / expired /
broker rejection), chunk contiguity, and the DataFrame contract above.

## Layout

| Path | Purpose |
| --- | --- |
| `fyers_client/config.py` | credential loading, resolution limits |
| `fyers_client/auth.py` | login URL, token exchange, unattended refresh, cache |
| `fyers_client/historical.py` | chunked fetch, retries, pandas conversion |
| `fyers_client/cli.py` | `login` / `refresh` / `status` / `check` / `history` |
| `scripts/verify_setup.py` | environment and connectivity diagnostic |
| `tests/test_pipeline.py` | offline test suite |

## Security

`.env` and `.fyers_token.json` are gitignored, and the token cache is written
`0600`. Never commit either — an access token is a live trading credential.
