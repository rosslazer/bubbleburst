# Evidence: Chromium virtual authenticator negative control (2026-09-16)

Environment: Headless Chromium 141.0.7390.37 (Playwright 1.56.1 bundled build), Linux x86_64,
CDP `WebAuthn.addVirtualAuthenticator` with `protocol: ctap2, ctap2Version: ctap2_1, transport:
internal, hasResidentKey, hasUserVerification, isUserVerified, automaticPresenceSimulation`.
Server: this harness, RP ID `localhost`, origin `http://localhost:8797`, no MDS loaded
(`HV_MDS_FETCH=false`, egress blocked).

Result (`pnpm run test:e2e`): 3 passed.

Server-verified facts recorded from the diagnostic lane:

- Registration `fmt: packed`, `attStmt` with `alg -7`, `sig`, `x5c` of one self-signed certificate,
  subject `C=US, O=Chromium, OU=Authenticator Attestation, CN=Batch Certificate`; no
  `id-fido-gen-ce-aaguid` extension; AAGUID `01020304-0506-0708-0102-030405060708`.
- Flags: UP=1, UV=1; BE/BS follow the virtual authenticator's `defaultBackupEligibility/State`.
- Library (`@simplewebauthn/server` 14.0.2) `verifyRegistrationResponse`: **verified: true**
  (no trust anchors configured for `packed`, so path validation was skipped by the library).
- Policy `strict-v1`: **REJECTED** — `METADATA_UNAVAILABLE`, `AAGUID_NOT_IN_METADATA`,
  `NO_TRUST_ANCHOR`, plus `BACKUP_ELIGIBLE_NOT_HARDWARE_BOUND` when BE=1.
- Authentication: library **verified: true**, counter 1→2 checked and increased, `approved: false`,
  `approvalToken: null`, reasons "credential did not meet strict attestation policy at enrollment".
- Demo site submission state after the strict-lane run: `awaiting-verification` (never accepted).
- Forged token posted to the site backend: HTTP 409 "Submission not accepted".

Client-reported (unsigned, contextual only): `transports: ["internal"]`, `authenticatorAttachment:
"platform"`, ceremony duration ≈ 15 ms, `hints: ["hybrid"]` requested and ignored by the virtual
authenticator.

Manually observed: headless, no dialogs; presence simulated automatically.
