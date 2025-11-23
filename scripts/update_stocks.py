import argparse
import json
import math
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yfinance as yf
except ImportError:  # pragma: no cover - handled in action environment
    yf = None


DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "stocks.json"
TICKERS: Dict[str, float] = {
    "NVDA": 140.0,
    "MSFT": 350.0,
    "GOOGL": 135.0,
    "META": 300.0,
    "AMZN": 120.0,
}

BAGHOLDER_SERIES = [
    {
        "label": "CoreWeave (est.)",
        "color": "#ef4444",
        "data": [
            {"x": "2025-01-02", "y": 100},
            {"x": "2025-01-09", "y": 94},
            {"x": "2025-01-16", "y": 88},
            {"x": "2025-01-23", "y": 77},
            {"x": "2025-01-30", "y": 64},
            {"x": "2025-02-06", "y": 53},
            {"x": "2025-02-13", "y": 50},
        ],
    },
    {
        "label": "Nebius (est.)",
        "color": "#22c55e",
        "data": [
            {"x": "2025-01-02", "y": 100},
            {"x": "2025-01-09", "y": 93},
            {"x": "2025-01-16", "y": 85},
            {"x": "2025-01-23", "y": 74},
            {"x": "2025-01-30", "y": 63},
            {"x": "2025-02-06", "y": 53},
            {"x": "2025-02-13", "y": 49},
        ],
    },
]


def _change_pct(series: List[float], days: int) -> float:
    if len(series) <= days:
        return 0.0
    past = series[-(days + 1)]
    latest = series[-1]
    if past == 0:
        return 0.0
    return round(((latest - past) / past) * 100, 2)


def _build_sample_dataset() -> dict:
    random.seed(1337)
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=365)

    dataset = {
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "series": {},
        "sentiment": {},
        "metadata": {
            "source": "sample",
            "note": "Generated offline; GitHub Actions will replace with live data when network is available.",
        },
        "bagholders": BAGHOLDER_SERIES,
    }

    for symbol, base_price in TICKERS.items():
        prices: List[float] = []
        timestamps: List[str] = []
        price = base_price

        for day in range(366):
            current_date = start + timedelta(days=day)
            seasonal = math.sin(day / 20) * 0.01
            drift = 0.0008
            noise = random.uniform(-0.004, 0.004)
            price = max(1.0, price * (1 + seasonal + drift + noise))
            prices.append(round(price, 2))
            timestamps.append(datetime.combine(current_date, datetime.min.time(), tzinfo=timezone.utc).isoformat())

        shares_outstanding = 24.5e9 if symbol == "NVDA" else 10e9
        market_cap = round(prices[-1] * shares_outstanding, 2)

        dataset["series"][symbol] = {
            "symbol": symbol,
            "timestamps": timestamps,
            "closes": prices,
            "sharesOutstanding": shares_outstanding,
            "marketCap": market_cap,
        }

        if symbol == "NVDA":
            dataset["sentiment"][symbol] = {
                "changePct5d": _change_pct(prices, 5),
                "changePct30d": _change_pct(prices, 30),
            }

    for symbol, info in BAGHOLDER_TICKERS.items():
        dataset["bagholders"].append(
            {
                "symbol": symbol,
                "label": info["label"],
                "color": info["color"],
                "data": _bagholder_downtrend(symbol, info["base"], today),
            }
        )

    return dataset


def _fetch_live_data() -> Optional[dict]:
    if yf is None:
        return None

    dataset = {
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "series": {},
        "sentiment": {},
        "metadata": {
            "source": "yfinance",
        },
        "bagholders": BAGHOLDER_SERIES,
    }

    for symbol in {**TICKERS, **{k: v["base"] for k, v in BAGHOLDER_TICKERS.items()}}:
        ticker = yf.Ticker(symbol)
        history = ticker.history(period="1y", interval="1d")
        if history.empty:
            return None

        closes = history["Close"].dropna().round(2)
        timestamps = [ts.to_pydatetime().replace(tzinfo=timezone.utc).isoformat() for ts in closes.index]
        prices = closes.tolist()

        fast_info = getattr(ticker, "fast_info", None)
        shares = None
        if fast_info:
            shares = getattr(fast_info, "shares_outstanding", None) or getattr(fast_info, "shares", None)
        info = getattr(ticker, "info", {}) or {}
        shares = shares or info.get("sharesOutstanding")

        market_cap = round(prices[-1] * shares, 2) if shares else None

        if symbol in TICKERS:
            dataset["series"][symbol] = {
                "symbol": symbol,
                "timestamps": timestamps,
                "closes": prices,
                "sharesOutstanding": shares,
                "marketCap": market_cap,
            }

            if symbol == "NVDA":
                dataset["sentiment"][symbol] = {
                    "changePct5d": _change_pct(prices, 5),
                    "changePct30d": _change_pct(prices, 30),
                }
        else:
            info = BAGHOLDER_TICKERS[symbol]
            dataset["bagholders"].append(
                {
                    "symbol": symbol,
                    "label": info["label"],
                    "color": info["color"],
                    "data": [{"x": ts, "y": price} for ts, price in zip(timestamps, prices)],
                }
            )

    return dataset


def write_dataset(dataset: dict) -> None:
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    DATA_PATH.write_text(json.dumps(dataset, indent=2))
    print(f"Wrote {DATA_PATH} with {len(dataset['series'])} tickers")


def main() -> None:
    parser = argparse.ArgumentParser(description="Update cached stock data for the AI bubble tracker.")
    parser.add_argument("--demo", action="store_true", help="Force sample data generation instead of live fetch.")
    args = parser.parse_args()

    dataset = None if not args.demo else _build_sample_dataset()

    if dataset is None:
        dataset = _fetch_live_data()

    if dataset is None:
        dataset = _build_sample_dataset()

    write_dataset(dataset)


if __name__ == "__main__":
    main()
