"""Command line entry points for the Fyers client.

    python -m fyers_client.cli login       # one interactive login
    python -m fyers_client.cli autologin   # unattended TOTP login, no browser
    python -m fyers_client.cli refresh     # unattended token renewal
    python -m fyers_client.cli status      # what is in the token cache
    python -m fyers_client.cli check       # verify credentials against /profile
    python -m fyers_client.cli history --symbol NSE:SBIN-EQ --resolution D \
        --start 2025-01-01 --end 2025-06-30 --out data/sbin.csv
"""

from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import parse_qs, urlparse

import pandas as pd

from fyers_client.autologin import AutoLoginError
from fyers_client.auth import AuthError, FyersAuth
from fyers_client.config import MissingCredentialsError, load_credentials
from fyers_client.historical import HistoricalClient, HistoryError


def _auth() -> FyersAuth:
    return FyersAuth(load_credentials())


def _pin(args: argparse.Namespace) -> str:
    return getattr(args, "pin", "") or os.getenv("FYERS_PIN", "").strip()


def _extract_auth_code(pasted: str) -> str:
    """Accept either a bare auth_code or the whole redirect URL."""
    pasted = pasted.strip()
    if "auth_code=" not in pasted:
        return pasted
    query = parse_qs(urlparse(pasted).query)
    codes = query.get("auth_code", [])
    if not codes:
        raise SystemExit("Could not find auth_code in the URL you pasted.")
    return codes[0]


def cmd_login(args: argparse.Namespace) -> int:
    auth = _auth()
    url = auth.login_url()
    print("1. Open this URL in a browser and log in to Fyers:\n")
    print(f"   {url}\n")
    print("2. After login you land on your redirect URL, which carries")
    print("   ?auth_code=... in the query string.\n")
    pasted = args.auth_code or input("3. Paste the auth_code (or the full URL): ")
    tokens = auth.exchange_auth_code(_extract_auth_code(pasted))
    print("\nAuthenticated. Tokens cached at", auth.cache_path)
    print("  access token expires :", tokens.access_expiry)
    print("  refresh token expires:", tokens.refresh_expiry)
    print("\nFrom here on, scheduled jobs can renew without a browser:")
    print("  python -m fyers_client.cli refresh")
    return 0


def cmd_autologin(args: argparse.Namespace) -> int:
    auth = _auth()
    if not auth.credentials.can_auto_login:
        print(
            "error: unattended login needs FYERS_ID, FYERS_PIN and "
            "FYERS_TOTP_SECRET in .env, alongside the app credentials.",
            file=sys.stderr,
        )
        return 1
    tokens = auth.auto_login()
    print("Logged in headlessly; tokens cached at", auth.cache_path)
    print("  access token expires :", tokens.access_expiry)
    print("  refresh token expires:", tokens.refresh_expiry)
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    auth = _auth()
    tokens = auth.refresh(_pin(args))
    print("Access token renewed; expires", tokens.access_expiry)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    status = _auth().status()
    print(f"token cache: {status['cache_path']}")
    for name in ("access_token", "refresh_token"):
        info = status[name]
        state = "valid" if info["valid"] else ("expired" if info["present"] else "absent")
        print(f"  {name:14s} {state:8s} expires={info['expires_at_utc']}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    auth = _auth()
    client = HistoricalClient(auth=auth, pin=_pin(args))
    profile = client.check_connection()
    print("Connected to Fyers as:")
    for key in ("name", "fy_id", "email_id"):
        if profile.get(key):
            print(f"  {key:9s} {profile[key]}")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    auth = _auth()
    client = HistoricalClient(auth=auth, pin=_pin(args))
    frame = client.fetch(
        symbol=args.symbol,
        resolution=args.resolution,
        start=args.start,
        end=args.end,
        cont_flag=args.cont_flag,
    )
    print(
        f"{args.symbol} {args.resolution}: {len(frame)} candles "
        f"in {frame.attrs['requests_made']} request(s)"
    )
    if not frame.empty:
        print(f"range: {frame.index[0]}  ->  {frame.index[-1]}\n")
        with pd.option_context("display.width", 120):
            print(frame.head(args.head))
            if len(frame) > args.head:
                print("...")
                print(frame.tail(args.head))
    if args.out:
        out = os.path.abspath(args.out)
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        if out.endswith(".parquet"):
            frame.to_parquet(out)
        else:
            frame.to_csv(out)
        print(f"\nwrote {len(frame)} rows to {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fyers_client", description="Fyers API v3 historical data client"
    )
    parser.add_argument("--pin", default="", help="Fyers PIN, for token refresh")
    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login", help="interactive login (run once)")
    login.add_argument("--auth-code", default="", help="skip the prompt")
    login.set_defaults(func=cmd_login)

    autologin = sub.add_parser(
        "autologin", help="full unattended login using the TOTP secret"
    )
    autologin.set_defaults(func=cmd_autologin)

    refresh = sub.add_parser("refresh", help="renew the access token, no browser")
    refresh.set_defaults(func=cmd_refresh)

    status = sub.add_parser("status", help="show cached token validity")
    status.set_defaults(func=cmd_status)

    check = sub.add_parser("check", help="verify the token against /profile")
    check.set_defaults(func=cmd_check)

    history = sub.add_parser("history", help="download historical candles")
    history.add_argument("--symbol", required=True, help="e.g. NSE:SBIN-EQ")
    history.add_argument("--resolution", default="D", help="D, 1, 5, 15, 60, ...")
    history.add_argument("--start", default="", help="YYYY-MM-DD")
    history.add_argument("--end", default="", help="YYYY-MM-DD (default: today)")
    history.add_argument("--cont-flag", default="1", dest="cont_flag")
    history.add_argument("--out", default="", help="write to .csv or .parquet")
    history.add_argument("--head", type=int, default=5, help="rows to preview")
    history.set_defaults(func=cmd_history)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (AuthError, AutoLoginError, HistoryError, MissingCredentialsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
