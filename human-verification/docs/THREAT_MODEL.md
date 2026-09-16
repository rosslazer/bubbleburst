# Threat model and remaining attacks

## Attacker capabilities assumed

- Full control of the browser/client: can send arbitrary WebAuthn responses, forge
  `transports`/`authenticatorAttachment`, strip or replace attestation, replay captured traffic.
- Unlimited software credentials (virtual authenticators, custom CTAP emulators, soft keys).
- Ability to hire human solvers, and to place real phones next to remotely controlled computers.

## What the strict policy stops (verified by tests)

| Attack | Control | Test |
|---|---|---|
| Software credential with `none` or self-attestation | Policy rejects; library-only verification is never trusted | unit: `ATTESTATION_ABSENT`, `SELF_ATTESTATION`; e2e: Chromium virtual authenticator |
| Full attestation chained to an attacker CA | Path validation to explicit anchors only | unit: `CHAIN_INVALID`, `AAGUID_NOT_IN_METADATA`; apple-format with foreign chain |
| Spoofed AAGUID in authenticator data | Leaf-certificate AAGUID extension cross-check + MDS lookup | unit |
| Revoked/compromised authenticator model | MDS `statusReports` | unit |
| Stale or missing metadata | fail closed | unit |
| Replayed assertion / reused challenge | single-use challenge bound to session+lane+ceremony, consumed before verification | api |
| Wrong origin / RP ID / challenge / signature / no UV | library checks with configured expectations | api |
| Token substitution across site/session/action/payload | binding stored at mint time, matched on redeem | api |
| Double redemption (including concurrent) | atomic transaction, one success | api (25 parallel) |
| Expired token/session/challenge | expiries rechecked at mint and redeem | api |
| Promoting an untrusted session by enrolling a trusted credential afterwards | approval requires a fresh assertion from a trusted credential; enrollment never changes state | api |
| Diagnostic lane or weaker paths minting tokens | lane is part of the challenge and credential binding; diagnostic routes have no token path | api, e2e |
| Forged token posted to the site backend | site redeems server-side | e2e |
| Cloned hardware key with counters | counter must increase when a counter is in use | api |

## What it does not stop (by design; documented, not hidden)

- **Paid human solvers with accepted authenticators.** A solver farm of FIDO-certified keys or of
  whatever phones eventually pass policy approves requests at human speed. The policy raises cost
  per approval (hardware, human time); it does not detect intent.
- **Nearby phones beside remotely controlled computers.** The native hybrid flow's Bluetooth
  proximity check is between the phone and the *computer running the browser*, which the attacker
  owns. Nothing about proximity reaches the server: WebAuthn assertions sign
  `authenticatorData || SHA-256(clientDataJSON)` only; transport is not covered, and the client can
  claim any transport.
- **Uniqueness.** Hardware backing gives no stable person or device identity and does not enforce
  one credential per human. One key can enroll unlimited discoverable credentials for this RP; the
  enrollment-per-IP limit is the only brake and is network-based.
- **Fresh biometric.** UV may be a PIN; security keys may cache PIN authorization; the metadata
  `isFreshUserVerificationRequired` flag is recorded, not enforced by this server (it cannot be).
- **Per-device compromise.** Attestation is per model. A device whose attestation key is intact but
  whose firmware is hostile still passes.
- **Availability abuse.** Attackers can burn sessions and challenges; rate limits bound this and
  can collaterally block shared networks.

## Residual risks in the prototype itself

- SQLite single-writer suits a prototype; a multi-node deployment needs a database with row-level
  atomic updates (the redeem statement is written to port directly).
- The demo site's API key is a shared secret in configuration.
- MDS/CRL fetching needs egress; in restricted networks the service fails closed and approves nothing
  for MDS-backed formats, which is the intended behaviour but must be monitored.
