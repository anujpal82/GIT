# Fyers API v3 — historical data client

Connects to [Fyers](https://myapi.fyers.in/) API v3, pulls historical candles,
and returns them as clean pandas DataFrames.

## Can I log in server-to-server?

**Not with client_id + secret alone — Fyers has no client-credentials grant.**
The secret cannot mint a token by itself; it only computes
`appIdHash = sha256("client_id:secret_key")`, which authenticates the *second*
leg. The first leg needs a login, because the token authorises a real trading
account under SEBI 2FA rules. The official `fyers-apiv3` SDK has no refresh or
machine-to-machine method either.

What this client does instead is escalate through three paths, cheapest first,
so a scheduled job never needs a human:

```
  cached access token   ──▶ still valid?           use it
        │ expired
        ▼
  refresh token         ──▶ + appIdHash + PIN      new access token   (~15 days)
        │ expired
        ▼
  TOTP auto-login       ──▶ fy_id + PIN + TOTP     new token pair     (indefinite)
```

`FyersAuth.access_token()` implements exactly that chain. With the TOTP
credentials set it is **fully unattended** — no browser, ever, including after
the refresh token dies. Both tokens are JWTs, so expiry comes from the `exp`
claim rather than a guessed window.

### What TOTP auto-login costs you

Be deliberate about this. The unattended path replays the browser login
headlessly against Fyers' **internal, undocumented endpoints** — the ones the
web app calls, not the published API:

| Step | Sends | Gets back |
| --- | --- | --- |
| `send_login_otp` | Fyers ID (base64) | `request_key` |
| `verify_otp` | `request_key` + TOTP | `request_key` |
| `verify_pin` | `request_key` + PIN (base64) | session token |
| `token` | session token + app id | redirect URL with `auth_code` |

The `auth_code` is then exchanged through the *documented* `/validate-authcode`,
the same as the interactive flow.

Two consequences worth accepting on purpose:

- **Your 2FA seed lives on the server.** Anyone with read access to `.env` can
  mint TOTPs and log in as you, which defeats the point of second-factor auth.
  Keep the file `0600`, keep it off shared machines, and prefer a secret
  manager if you have one.
- **These endpoints carry no compatibility promise** and have moved hosts
  before. Every URL is overridable via `FYERS_LOGIN_BASE` or the per-step
  variables in `.env.example`, so a change on Fyers' side is a config edit
  rather than a code change. Check Fyers' terms before automating the login.

If you would rather not take that on, leave the three TOTP variables unset:
the client falls back to interactive login plus refresh-token renewal, which
runs unattended for about 15 days at a stretch.

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
python -m fyers_client.cli autologin  # no browser at all (needs the TOTP vars)
python -m fyers_client.cli check      # verifies the token against /profile
python -m fyers_client.cli refresh    # renew from the refresh token
python -m fyers_client.cli status     # what is in the token cache

python -m fyers_client.cli history \
    --symbol NSE:SBIN-EQ --resolution D \
    --start 2023-01-01 --end 2025-12-31 --out data/sbin.csv
```

From Python:

```python
from fyers_client import FyersAuth, HistoricalClient

# With the TOTP variables set, this authenticates itself -- no login step.
client = HistoricalClient(auth=FyersAuth())
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

45 tests, no network and no credentials required: every Fyers HTTP call is
replaced with a fake of the documented response shape. They cover the appIdHash
formula, JWT expiry parsing, the full token escalation (cached / refresh /
auto-login / exhausted), the four login steps and their per-step failures,
chunk contiguity, and the DataFrame contract above.

The TOTP generator is checked against the **RFC 6238 Appendix B test vectors**,
so a bad code is ruled out as a cause before you go debugging an opaque
"invalid OTP" from the broker.

## Layout

| Path | Purpose |
| --- | --- |
| `fyers_client/config.py` | credential loading, resolution limits |
| `fyers_client/auth.py` | login URL, token exchange, refresh, escalation, cache |
| `fyers_client/totp.py` | RFC 6238 TOTP, standard library only |
| `fyers_client/autologin.py` | headless four-step login (undocumented endpoints) |
| `fyers_client/historical.py` | chunked fetch, retries, pandas conversion |
| `fyers_client/cli.py` | `login` / `refresh` / `status` / `check` / `history` |
| `scripts/verify_setup.py` | environment and connectivity diagnostic |
| `tests/test_pipeline.py` | auth lifecycle, chunking, DataFrame contract |
| `tests/test_totp.py` | RFC 6238 vectors |
| `tests/test_autologin.py` | the four login steps and their failure modes |

## Security

`.env` and `.fyers_token.json` are gitignored, and the token cache is written
`0600`. Never commit either — an access token is a live trading credential, and
with TOTP configured `.env` additionally holds your 2FA seed, PIN and Fyers ID.
That one file is enough to take over the account, so treat it accordingly:
restrict its permissions, keep it off shared boxes and out of backups, and move
it into a secret manager if you have one.
