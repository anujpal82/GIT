"""One-command diagnostic: environment, credentials, network, pandas pipeline.

Run this first on any new machine. It reports what is ready and what is
missing, and it exercises the candle->DataFrame conversion on a sample payload
so the pandas half is proven even before credentials exist.

    python scripts/verify_setup.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

OK, BAD, WARN = "[ ok ]", "[fail]", "[warn]"

# A real /data/history response body, trimmed to three daily candles.
SAMPLE = {
    "s": "ok",
    "candles": [
        [1748889000, 812.50, 818.90, 809.15, 816.40, 9_482_331],
        [1748975400, 816.80, 822.00, 813.20, 819.75, 8_115_002],
        [1749061800, 820.00, 820.65, 806.40, 808.90, 11_204_887],
    ],
}


def check_packages() -> bool:
    ok = True
    try:
        import pandas as pd

        print(f"{OK} pandas {pd.__version__}")
    except ImportError:
        print(f"{BAD} pandas not installed -- pip install -r requirements.txt")
        ok = False
    try:
        import fyers_apiv3  # noqa: F401
        from fyers_apiv3 import fyersModel  # noqa: F401

        print(f"{OK} fyers-apiv3 importable (fyersModel.FyersModel.history present)")
    except ImportError:
        print(f"{BAD} fyers-apiv3 not installed -- pip install -r requirements.txt")
        ok = False
    return ok


def check_credentials() -> bool:
    from fyers_client.config import ENV_PATH, load_credentials

    creds = load_credentials()
    print(f"\n-- credentials ({'.env found' if ENV_PATH.exists() else 'no .env file'})")
    ok = True
    for field in ("client_id", "secret_key", "redirect_uri"):
        if getattr(creds, field):
            value = getattr(creds, field)
            shown = value if field == "redirect_uri" else f"{value[:4]}...{value[-3:]}"
            print(f"{OK} FYERS_{field.upper():13s} {shown}")
        else:
            print(f"{BAD} FYERS_{field.upper():13s} not set")
            ok = False
    return ok


def check_tokens() -> None:
    from fyers_client.auth import FyersAuth
    from fyers_client.config import load_credentials

    status = FyersAuth(load_credentials()).status()
    print("\n-- tokens")
    for name in ("access_token", "refresh_token"):
        info = status[name]
        if info["valid"]:
            print(f"{OK} {name:14s} valid until {info['expires_at_utc']} UTC")
        elif info["present"]:
            print(f"{WARN} {name:14s} expired at {info['expires_at_utc']} UTC")
        else:
            print(f"{WARN} {name:14s} absent -- run: python -m fyers_client.cli login")


def check_network() -> bool:
    """Probe the API over HTTPS, the same path real calls take.

    A bare TCP connect is not enough: a proxy can accept the socket and still
    refuse the tunnel, so this issues a real request and treats any HTTP
    response -- including an unauthenticated rejection -- as reachable.
    """
    import requests

    from fyers_client.auth import API_BASE

    print("\n-- network")
    try:
        response = requests.get(f"{API_BASE}/profile", timeout=15)
    except requests.RequestException as exc:
        print(f"{BAD} cannot reach {API_BASE} over HTTPS")
        print(f"       {type(exc).__name__}: {exc}")
        print("       A corporate proxy or egress policy blocking the host")
        print("       causes this; the API itself may be perfectly healthy.")
        return False
    print(f"{OK} {API_BASE} answered HTTP {response.status_code}")
    return True


def check_pandas_pipeline() -> bool:
    import pandas as pd

    from fyers_client.historical import candles_to_dataframe

    print("\n-- pandas pipeline (sample payload, no network)")
    frame = candles_to_dataframe(SAMPLE["candles"])
    with pd.option_context("display.width", 120):
        print(frame.to_string())
    checks = {
        "rows parsed": len(frame) == 3,
        "index is tz-aware IST": str(frame.index.tz) == "Asia/Kolkata",
        "OHLCV are float64": all(str(frame[c].dtype) == "float64" for c in frame),
        "index sorted": frame.index.is_monotonic_increasing,
    }
    for label, passed in checks.items():
        print(f"{OK if passed else BAD} {label}")
    print(f"\n     resampled weekly close:\n{frame['close'].resample('W').last()}")
    return all(checks.values())


def main() -> int:
    print("== Fyers client setup check ==\n-- packages")
    packages = check_packages()
    if not packages:
        return 1
    credentials = check_credentials()
    check_tokens()
    network = check_network()
    pipeline = check_pandas_pipeline()

    print("\n== summary ==")
    print(f"{OK if pipeline else BAD} pandas conversion works offline")
    print(
        f"{OK if credentials else WARN} credentials "
        f"{'present' if credentials else 'missing -- copy .env.example to .env'}"
    )
    print(
        f"{OK if network else WARN} Fyers API "
        f"{'reachable' if network else 'unreachable from here'}"
    )
    if credentials and network:
        print("\nNext: python -m fyers_client.cli login")
    return 0 if pipeline else 1


if __name__ == "__main__":
    raise SystemExit(main())
