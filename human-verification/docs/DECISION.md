# Decision report: no-install human verification via cross-device passkeys

Prepared 2026-09-16 from the harness in this directory, its automated tests, one real-browser
negative control, and the documentary research in `evidence/research-2026-09-16.md`.

## Verdict

**Inconclusive on real devices; the available documentary evidence points to No-go for the
proposed broad phone flow, with a Restricted-feasibility path.**

- *Inconclusive* because the required real-device matrix (iPhone/iCloud Keychain and
  Android/Google Password Manager through desktop cross-device enrollment and authentication,
  Bluetooth-off variants, a hardware security key positive control) could not be run in this
  environment: no phones, no reachable HTTPS hostname, and outbound network limited to package
  registries (the FIDO MDS BLOB and vendor documentation hosts were unreachable). Those rows are
  recorded as **UNTESTED** in `docs/DEVICE_MATRIX.md` with exact instructions.
- *Pointing to No-go* because Apple states, in its own developer-forum answers by Apple staff, that
  iCloud Keychain passkeys "don't support attestation" and return `fmt: none`; Google stated at
  launch that Android passkeys "will not initially have any attestation"; Microsoft documents that
  synced passkeys do not support attestation; and neither the Apple Passwords nor the Google
  Password Manager AAGUID appears in the FIDO MDS. Under the strict policy this harness implements,
  a `none` attestation is rejected with `ATTESTATION_ABSENT`, deliberately and without a way to
  weaken it into apparent success. If the device tests confirm `fmt: none`, ordinary phone passkeys
  cannot satisfy the premise ("trustworthy attestation from ordinary phone authenticators"), and
  the outcome is No-go for a universal phone CAPTCHA.
- *Restricted feasibility* remains for audiences that hold authenticators with verifiable
  provenance: FIDO-certified roaming security keys listed in the MDS (the positive-control class,
  demonstrated here only with a labelled fixture), Windows Hello hardware authenticators (`tpm`,
  in MDS; desktop, not phone; needs the matcher-protection knob relaxed), and organisation-managed
  Apple devices using DDM passkey attestation (chains to the *organisation's* CA, needs MDM and a
  per-tenant anchor). That is a restricted-audience product, not a universal phone CAPTCHA.

Do not read any of the harness's passing tests as evidence that phones pass. The only positive
results are from a clearly labelled fixture authenticator.

## What the harness proves (automated, this environment)

Vitest: 49 tests (unit + API over the HTTP contract). Playwright: 3 tests in Chromium
141.0.7390.37 with a CDP virtual authenticator. All passing.

| Requirement | Result |
|---|---|
| Virtual/software authenticator: ordinary registration/authentication works, strict policy rejects, no approval | Chromium virtual authenticator returned `packed` with a self-signed "C=US, O=Chromium, OU=Authenticator Attestation, CN=Batch Certificate" chain, AAGUID `01020304-…`; library verified; policy `REJECTED` (`AAGUID_NOT_IN_METADATA`, `NO_TRUST_ANCHOR`, `METADATA_UNAVAILABLE`, `BACKUP_ELIGIBLE…` when BE=1); form never accepted; diagnostic lane echoes evidence with `approvalToken: null`. |
| Missing attestation, self-attestation, unknown roots, malformed statements, spoofed AAGUID/transport | Rejected with `ATTESTATION_ABSENT`, `SELF_ATTESTATION`, `CHAIN_INVALID`/`AAGUID_NOT_IN_METADATA`, `LIBRARY_VERIFICATION_FAILED`/`MALFORMED_ATTESTATION`, `AAGUID_MISMATCH`; transports are labelled client-reported and never affect the verdict. |
| Missing UV, bad signature, wrong origin/RP ID/challenge, expired challenge | Rejected at registration and authentication; session stays pending. |
| Replayed assertions, reused enrollment challenges, session swapping | Rejected before signature verification by single-use, session-bound challenges. |
| Cross-session/site/action/payload token substitution | `BINDING_MISMATCH`, token not consumed. |
| Expired tokens; concurrent redemption | `TOKEN_EXPIRED`; 25 parallel redemptions → exactly one success. |
| Enrollment cannot silently convert an untrusted session | Enrollment never changes state; untrusted credential still fails after a trusted one is enrolled; only a fresh trusted assertion approves. |
| Diagnostic mode and weaker paths cannot mint strict tokens | Lane is part of challenge and credential binding; diagnostic routes have no token path; forged tokens refused by the site backend. |
| Positive attestation verification uses labelled fixtures only | Fixture CA + fixture MDS BLOB, programmatic-only anchors, `FIXTURE:` label in verdicts; no environment path to add roots. |
| Vendor root pinning | Embedded Apple WebAuthn Root CA fingerprint checked at startup; mismatch aborts (tested). |

Both flows were exercised end to end against the API with the fixture authenticator: first use
(form → enrollment → strict verdict → fresh assertion → token → redeem) and returning use (form →
fresh assertion from a previously enrolled trusted credential → token → redeem).

## What is not proven

- That any ordinary iPhone or Android phone passkey yields acceptable attestation (documentary
  evidence says it does not).
- That the native cross-device UI appears in each desktop/phone combination with the `hints:
  ["hybrid"]` request (Chrome 128+ honours `hints`; Safari and Firefox ignore them per the IDLs
  found in research §4). Recorded as UNTESTED.
- Anything about Bluetooth proximity. The server receives no signed statement of transport; this
  harness displays transports as client-reported and does not use them.
- Uniqueness of a human, or that UV was biometric.

## UX friction (documented, not measured)

Not measured on real devices in this environment. From the browser flow itself: first use requires
a QR scan on the phone, a Bluetooth proximity check, phone unlock/UV, a passkey save prompt, then
a *second* ceremony (fresh assertion) before the form is accepted. Returning use is one ceremony
but still QR + Bluetooth + UV on desktop. Expect this to be materially slower than a CAPTCHA and
to fail wherever Bluetooth is off, the phone is far away, or the desktop browser lacks hybrid
support. The diagnostics page records ceremony duration and observed UX per row.

## Costs (recorded, not established as free at scale)

| Item | Prototype | Notes |
|---|---|---|
| Compute | One Node process + SQLite | Multi-node needs a shared DB with atomic updates; the redeem statement ports directly. |
| TLS + hostname | Required for real devices | Certificates via Let's Encrypt or a tunnel; RP ID stability matters for returning users. |
| FIDO MDS | Free download under FIDO's legal terms | Operational: refresh on `nextUpdate`, monitor root rotation (GlobalSign R46 rotation in Aug 2026 broke libraries pinning only R3). |
| Vendor roots / revocation lists | Free | Google root 1 expired 2026-05; Android status list needs egress. |
| Storage | One row per discoverable credential per visitor | Unbounded growth without expiry; each visitor also consumes a resident-key slot on their authenticator for this RP. |
| Abuse controls | Rate limits in DB | Shared-network collateral; no uniqueness. |
| Third-party services | None | No paid verification API is used. |

Free operation at scale is therefore plausible on the infrastructure side but not established, and
the dominant cost is operational (metadata hygiene, policy maintenance, support for failed
ceremonies).

## Remaining tests

The full real-device matrix in `docs/DEVICE_MATRIX.md`, run per `docs/MANUAL_TESTS.md` on an HTTPS
hostname with MDS fetch enabled. Priority order: (1) iPhone + iCloud Keychain, desktop Chrome and
Safari, enrollment then authentication; (2) Android + Google Password Manager, desktop Chrome;
(3) hardware security key positive control (needs live MDS); (4) Bluetooth-off / phone-remote
variants; (5) Firefox and Windows desktop combinations.

If (1) and (2) show `fmt: none` as documented, record No-go for the broad flow and consult
`docs/ALTERNATIVES_AND_COSTS.md`, which does not implement anything and requires a new scope
decision.
