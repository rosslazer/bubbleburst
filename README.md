# AI Bubble Burst Tracker

A tongue-in-cheek single-page site that charts the AI hype cycle using cached stock data for AI-heavy tickers.

## How stock data works
- A GitHub Action (see `.github/workflows/update-stocks.yml`) runs every 30 minutes and on demand to refresh `data/stocks.json` using free Yahoo Finance data via `yfinance`.
- The front-end fetches that JSON file (no API keys or paid services required) to render the chart, market-cap callout, and sentiment gauge.
- When network access is unavailable, the `scripts/update_stocks.py` script falls back to deterministic sample data so the page still renders locally.

## Local development
1. Install dependencies for the updater script (only needed if you want to refresh data locally):
   ```bash
   python -m pip install --upgrade pip
   pip install yfinance
   ```
2. Refresh cached stock data (uses live data when available, otherwise sample data):
   ```bash
   python scripts/update_stocks.py
   ```
3. Serve the site locally with any static server (for example):
   ```bash
   python -m http.server 8000
   ```
   Then open http://localhost:8000 in your browser.

## Manual sample data
If you want to force sample data without hitting Yahoo Finance, run:
```bash
python scripts/update_stocks.py --demo
```

## Notes
- The GitHub Action commits updates to `data/stocks.json` using the repository's `GITHUB_TOKEN`.
- The chart includes NVDA, MSFT, GOOGL, META, and AMZN; add or remove tickers by editing `scripts/update_stocks.py` and re-running the updater.

## Deploying to GitHub Pages
1. In the repo settings, open **Pages** and set the source to **GitHub Actions**.
2. The included workflow `.github/workflows/deploy-pages.yml` publishes the root of the repository (including `data/stocks.json`) to the `github-pages` environment on every push to `main` or via **Run workflow**.
3. After the first deploy, GitHub shows the public URL in the workflow summary and on the Pages settings screen. For a project site, it will usually look like `https://<username>.github.io/<repo>/`.

