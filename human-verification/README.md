# Human verification prototype (no-install, cross-device passkey)

Feasibility harness for a CAPTCHA alternative: a visitor submits a web form, approves it with a
passkey on a nearby phone through the browser's **native** cross-device (hybrid/QR) flow, and is
returned to the form. No app install. A **strict attestation trust policy** decides whether the
credential that signed the approval is backed by an authenticator whose provenance and security
properties can be independently verified.

This is an evidence harness plus a decision report, not a product widget. Read
[`docs/DECISION.md`](docs/DECISION.md) first for the go/no-go assessment.

What a successful approval means: *"the assertion came from a credential whose enrollment evidence
met the configured authenticator policy, bound to this exact site, action and submission."* It does
**not** mean a unique human, Bluetooth proximity, or a biometric gesture.

## Layout

```
human-verification/
  src/
    config.ts                 explicit configuration (env → AppConfig); fixture anchors are programmatic-only
    db.ts                     SQLite schema (public keys, verdicts, token hashes; no secrets, no biometrics)
    policy/
      attestationPolicy.ts    strict-v1 trust policy layer (independent of the WebAuthn library's verdict)
      mds.ts                  FIDO MDS v3 BLOB loading/verification/freshness
      trustStore.ts           explicit anchors: MDS per-AAGUID roots, pinned vendor roots, labelled fixtures
    services/
      sessions.ts             sessions, challenges, one-time approval tokens (pending→approved→consumed)
      credentials.ts          credential records with policy verdict + version
      webauthnService.ts      ceremonies bound to session/lane; counter and UV semantics
    routes/verification.ts    Phase-2 integration contract (sessions, options/verify, status, redeem)
    routes/diagnostics.ts     diagnostic lane (same policy evaluator, never issues tokens)
    demo-site/routes.ts       demo relying site backend (digest, site key, server-side redeem)
    app.ts, server.ts         assembly and Node server
  public/                     demo form, verification page, diagnostics page (first-party, one RP ID)
  test/
    unit/                     policy rules, session/token state machine, rate limiter
    api/                      full flows and security boundaries via the HTTP contract
    e2e/                      Playwright + Chromium virtual authenticator (negative control)
    helpers/                  FIXTURE authenticator + FIXTURE MDS BLOB (test-only, clearly labelled)
  docs/                       decision report, policy, threat model, device matrix, manual test plan
  evidence/                   documentary research and exported runs
  scripts/export-evidence.ts  sanitized evidence export
```

## Requirements

- Node.js 22.12+ (uses `node:crypto` WebCrypto and prebuilt `better-sqlite3`)
- pnpm 10.33 (`corepack enable` or `npm i -g pnpm@10.33.0`)
- For the e2e suite: Playwright's Chromium (`pnpm exec playwright install chromium`), or set
  `HV_CHROMIUM_PATH` to an existing Chromium binary.

All dependencies are pinned exactly in `package.json` and `pnpm-lock.yaml`.

## Run locally

```bash
pnpm install
pnpm start                       # http://localhost:8787  (RP ID "localhost", MDS download attempted)
```

Pages: `/demo/` (form → verify → return), `/verify` (verification page), `/diagnostics`
(evidence harness), `/policy` (JSON: policy, MDS status, trust anchors and fingerprints).

On `localhost`, WebAuthn works over plain HTTP in browsers, but the **cross-device phone flow does
not**: real-phone tests require HTTPS on a hostname the phone's browser trusts.

## Real-device testing over HTTPS

The RP ID must equal (or be a registrable suffix of) the hostname of the verification page. Pick one
of:

1. **Tunnel** (fastest): `cloudflared tunnel --url http://localhost:8787` or `ngrok http 8787`.
   Set `HV_ORIGIN=https://<tunnel-host>` and `HV_RP_ID=<tunnel-host>`, restart. Every new random
   tunnel hostname is a new RP ID: previously enrolled passkeys will not be listed. Use a reserved
   hostname for the returning-user tests.
2. **Reverse proxy with a real certificate**: Caddy (`caddy reverse-proxy --from verify.example.com --to localhost:8787`)
   or nginx + Let's Encrypt on a small VM. Set `HV_TRUST_PROXY=true` so rate limits see the client IP.

Then follow [`docs/MANUAL_TESTS.md`](docs/MANUAL_TESTS.md) and record rows on `/diagnostics`.

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `HV_ORIGIN` | `http://localhost:8787` | First-party origin of the verification page |
| `HV_RP_ID` | hostname of origin | WebAuthn RP ID |
| `HV_PORT` | `8787` | Listen port |
| `HV_DB_PATH` | `data/hv.sqlite` | SQLite file, or `:memory:` |
| `HV_SITES_JSON` | demo site | `[{"id","name","apiKey"}]` relying sites and their API keys |
| `HV_MDS_FETCH` | `true` | Download the FIDO MDS BLOB at startup / when `nextUpdate` passes |
| `HV_MDS_URL` | `https://mds3.fidoalliance.org/` | MDS v3 endpoint |
| `HV_MDS_BLOB_PATH` | `data/mds-blob.jwt` | Cached BLOB (verified on load; used when fetching is off/fails) |
| `HV_SESSION_TTL_SEC` / `HV_CHALLENGE_TTL_SEC` / `HV_TOKEN_TTL_SEC` | 600 / 120 / 120 | Expirations |
| `HV_POLICY_ALLOW_BACKUP_ELIGIBLE` | `false` | Accept BE=1 credentials (see POLICY.md) |
| `HV_POLICY_REQUIRE_FIDO_CERTIFIED` | `true` | Require a FIDO_CERTIFIED* status in MDS |
| `HV_POLICY_REQUIRE_MATCHER_BEYOND_SOFTWARE` | `true` | Reject software-only matcher protection |
| `HV_POLICY_REJECT_STALE_MDS` | `true` | Fail closed when the BLOB is past `nextUpdate` |
| `HV_POLICY_VENDOR_ROOT_APPLE` / `HV_POLICY_VENDOR_ROOT_ANDROID_KEY` | `true` | Enable vendor roots for `apple` / `android-key` |
| `HV_POLICY_ANDROID_KEY_REVOCATION_CHECK` | `true` | Consult Google's attestation status list (fail closed if unreachable) |
| `HV_RL_*_MAX` / `HV_RL_*_WINDOW_SEC` | see `config.ts` | Rate limits per site / IP / session / credential |
| `HV_TRUST_PROXY` | `false` | Use `X-Forwarded-For` for client IP |
| `HV_DIAGNOSTICS_ENABLED` | `true` | Serve the diagnostic lane |

There is deliberately **no** environment variable for extra trust anchors. Fixture roots can only be
injected programmatically by tests (`policy.fixtureTrustAnchors`), and every verdict that used one is
labelled `FIXTURE`.

## Tests

```bash
pnpm run typecheck
pnpm test            # unit + API (vitest, in-memory SQLite, fixture authenticator + fixture MDS)
pnpm run test:e2e    # Playwright: Chromium virtual authenticator negative control
```

Coverage of the required security boundaries is listed in `docs/DECISION.md` §"What the harness proves".

## Evidence export

```bash
HV_DB_PATH=data/hv.sqlite pnpm run evidence:export
```

writes `evidence/exports/evidence-<timestamp>.json` with policy summary, trust anchors, diagnostic
runs and credential verdicts (no public keys, no secrets).

## Existing repository

This directory is self-contained and does not touch the static site at the repository root. The
GitHub Pages workflow publishes the repository root; nothing here needs to be built for it.
