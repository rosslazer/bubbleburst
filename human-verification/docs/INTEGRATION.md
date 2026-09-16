# Integration contract (Phase 2)

All requests and responses are JSON. Site endpoints authenticate with `Authorization: Bearer <site
api key>`. Client endpoints authenticate with the `X-Client-Token` header issued at session
creation and delivered to the verification page in the URL fragment (never sent to servers as a
query string or Referer).

## `POST /verification-sessions` (site)

```json
{ "action": "contact-form:submit", "submissionDigest": "<sha256 hex of the canonical submission>", "returnUrl": "https://site.example/complete" }
```
→ `201 { session: {id, state:"pending", action, submissionDigest, expiresAt, ...}, clientToken, verifyUrl }`

The digest is computed by the site backend over the exact payload it will accept. Any change to the
form produces a new digest and therefore requires a new session and a new approval.

## `GET /verification-sessions/:id`

With a site key of the owning site: full view. With the client token: limited view. Otherwise 403.
Unknown IDs are 404 in both cases.

## `POST /verification-sessions/:id/registration/options|verify` and `.../authentication/options|verify` (client)

Each `options` call stores a fresh 256-bit challenge bound to `(session, lane, ceremony)` with a
short expiry. `verify` extracts the challenge from the signed `clientDataJSON`, consumes it
atomically (single use), and only then runs library verification with the configured origin and RP
ID. Registration returns the policy verdict and never approves. Authentication returns
`approved: true` and an `approvalToken` only when the assertion verifies against a credential whose
stored verdict is `TRUSTED` under the current policy version, in the strict lane, with UV, and while
the session is still pending and within rate limits.

## `POST /redeem` (site)

```json
{ "approvalToken": "hvt_…", "sessionId": "vs_…", "action": "contact-form:submit", "submissionDigest": "<hex>" }
```
→ `200 { ok: true, session: {...state:"consumed"}, credentialId, assurance: "credential-meets-configured-authenticator-policy" }`
or `409 { ok: false, reason: TOKEN_UNKNOWN | TOKEN_ALREADY_CONSUMED | TOKEN_EXPIRED | BINDING_MISMATCH | SESSION_NOT_APPROVED }`.

Tokens are 256-bit random values with an `hvt_` prefix; only their SHA-256 is stored. Redemption is
a single SQLite transaction whose `UPDATE … WHERE consumed_at IS NULL AND expires_at > now AND
site_id = ? AND session_id = ? AND action = ? AND submission_digest = ?` guarantees exactly one
success under concurrency (tested with 25 parallel attempts). A mismatched binding never consumes
the token.

## State machine

`pending → approved → consumed`; `pending → expired` (lazy, on read); `pending → rejected`
(operator/abuse). A session receives at most one token. Enrollment never changes state.

## CSRF and session swapping

- Client mutation endpoints require JSON bodies and a custom header, so cross-site form posts fail
  the CORS preflight; an `Origin` header, when present, must equal the configured origin.
- The client token is a per-session bearer secret; possessing a session ID is not enough.
- Challenges are bound to the session that requested them; an assertion produced for session A is
  rejected in session B before any signature check.
- The site backend redeems server-side; the token arriving in the browser is transport, not
  authorization.

## One RP ID, one first-party page — and how a hosted widget would keep the boundary

The prototype uses a single RP ID and a top-level verification page on the same origin as the API.
WebAuthn credentials are scoped to the RP ID, and browsers only allow `navigator.credentials.*`
from a top-level document of that RP or from a cross-origin iframe explicitly delegated with
`Permissions-Policy: publickey-credentials-get/create` by the embedding page. A hosted widget would
therefore keep the ceremony on the verification service's own origin — either by a top-level
redirect (as the prototype does) or by an iframe that the *site* delegates permission to — and the
credential stays scoped to the verification service's RP ID, shared across all sites it serves.
That is by design: the passkey belongs to the verification service, not to each site, and there is
no cross-site credential sharing to arrange. What must never be done is proxying the ceremony
through the site's origin or hiding the browser's permission model with iframe tricks; the origin
recorded in `clientDataJSON` would not match and the assertion would (correctly) fail.

## Rate limits (prototype controls)

Per site (sessions/min, redeems/min), per IP (sessions/min, enrollments/hour, diagnostics), per
session (ceremony attempts), per credential (approvals/hour). Sliding window in SQLite. These raise
cost; they do not create uniqueness. IP limits affect shared networks; credential limits are evaded
by enrolling a new credential (which the enrollment-per-IP limit then constrains).
