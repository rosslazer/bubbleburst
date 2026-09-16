# Attestation trust policy (`strict-v1`)

## Why a separate policy layer

`@simplewebauthn/server` answers "is this response well-formed and consistent with the challenge,
origin, RP ID and signature?". It returns `verified: true` for `fmt: none`, for packed
self-attestation, and (when no trust anchors are configured for a format) for a full attestation
whose chain reaches an unknown root: `validateCertificatePath` skips path validation when the
anchor list is empty. Its `MetadataService` "strict" mode only affects formats that consult
metadata (`packed`, `tpm`, `android-key`, `android-safetynet`); `none`, `apple` and `fido-u2f`
never touch it. A library "success" is therefore not a trusted-hardware verdict.

`src/policy/attestationPolicy.ts` evaluates every registration independently and fails closed.
Each verdict lists its checks, labelled by basis:

- **server-verified**: computed by this server (decoding, flags, chain path validation, AAGUID
  consistency, Android security levels, library precondition).
- **documented**: taken from a trusted publisher's metadata (FIDO MDS entry, vendor root source).
- **client-reported**: supplied by the browser (`transports`, `authenticatorAttachment`). Contextual
  only, never evidence. They do not indicate which transport was used for any assertion.

## Rules

| Step | Rule | Rejection code |
|---|---|---|
| 0 | Library verification must have passed (precondition, not a verdict) | `LIBRARY_VERIFICATION_FAILED` |
| 1 | Attestation object decodes | `MALFORMED_ATTESTATION` |
| 2 | UV flag set at enrollment | `USER_VERIFICATION_MISSING` |
| 3 | `fmt: none` → reject | `ATTESTATION_ABSENT` |
| 3 | `fmt` must be one of `packed`, `tpm`, `android-key`, `apple` | `FORMAT_NOT_ALLOWED` / `UNSUPPORTED_EVIDENCE` (`android-safetynet` is decommissioned; `fido-u2f` cannot carry UV) |
| 4 | `x5c` present; packed without `x5c` is self-attestation | `SELF_ATTESTATION` / `CHAIN_ABSENT` |
| 5 (packed/tpm) | MDS loaded and not past `nextUpdate` | `METADATA_UNAVAILABLE` / `METADATA_STALE` |
| 5 | AAGUID has an MDS entry | `AAGUID_NOT_IN_METADATA` |
| 5 | No `REVOKED`, `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_*_COMPROMISE` status | `METADATA_STATUS_UNACCEPTABLE` |
| 5 | At least one `FIDO_CERTIFIED*` status (configurable) | `METADATA_NOT_CERTIFIED` |
| 5 | `attestationTypes` includes `basic_full` or `attca` | `METADATA_NO_FULL_ATTESTATION` |
| 5 | `keyProtection` includes `hardware` and (`secure_element` or `tee`), excludes `software`/`remote_handle` | `METADATA_KEY_PROTECTION_UNACCEPTABLE` |
| 5 | `matcherProtection` includes `tee` or `on_chip` (configurable) | `METADATA_MATCHER_PROTECTION_UNACCEPTABLE` |
| 5 | `userVerificationDetails` has a combination beyond presence | `METADATA_NO_UV_METHOD` |
| 6 (packed/tpm) | Leaf `id-fido-gen-ce-aaguid` extension, if present, equals authenticator-data AAGUID | `AAGUID_MISMATCH` |
| 7 | Chain validates to an explicit anchor set for this format/AAGUID | `NO_TRUST_ANCHOR` / `CHAIN_INVALID` |
| 8 (apple) | Library verified the nonce binding; chain reaches the pinned Apple WebAuthn Root CA | `LIBRARY_VERIFICATION_FAILED` / `CHAIN_INVALID` |
| 8 (android-key) | `attestationSecurityLevel` and `keymasterSecurityLevel` ≥ TEE; chain reaches a pinned Google root; no serial on Google's revocation list (fail closed if unreachable) | `ANDROID_SECURITY_LEVEL_UNACCEPTABLE` / `ANDROID_CERT_REVOKED` / `ANDROID_REVOCATION_UNAVAILABLE` |
| 9 | BE=1 rejected unless `allowBackupEligible` | `BACKUP_ELIGIBLE_NOT_HARDWARE_BOUND` |

`trusted` is true only when no rejection code was raised **and** the chain check passed.

## Trust anchors and their sources

| Anchor set | Source | Freshness / revocation |
|---|---|---|
| FIDO MDS v3 per-AAGUID `attestationRootCertificates` | BLOB from `https://mds3.fidoalliance.org/`, JWT chain validated against GlobalSign Root CA R3 / Root R46 (pinned copies in the library, fingerprints checked in `trustStore.ts`) | BLOB `no` must increase; refetched when `nextUpdate` passes; stale BLOB → fail closed (default). `statusReports` drive revocation/compromise rejection. |
| Apple WebAuthn Root CA (`apple` format) | Published PEM at apple.com/certificateauthority; embedded copy pinned by SHA-256 `0915dd5c…f9bb29`; startup aborts on mismatch | Long-lived root (2045). No vendor revocation feed for this CA. |
| Google Hardware Attestation Roots 1–4 (`android-key`) | developer.android.com key attestation page; embedded copies | Root 1 expired 2026-05-24 and is filtered out automatically. Revocation via `https://android.googleapis.com/attestation/status` (serial list), fail closed when unreachable. |
| Fixture roots | Test-only, programmatic (`policy.fixtureTrustAnchors`), applied only to MDS-backed formats and only when the fixture MDS entry lists them; label `FIXTURE:` in every verdict | Never loaded from environment; never present in a deployment. |

The library's `packed` verifier is additionally initialised with the same MDS statements in
*permissive* mode so that it cross-checks algorithms and roots when an AAGUID is known, while this
policy layer owns strictness and produces explainable rejections.

## What passes, in principle

- FIDO-certified roaming security keys with MDS entries declaring hardware key protection and a UV
  method (PIN or on-key biometric). Positive control class.
- Any authenticator whose vendor publishes verifiable metadata meeting the rules above.
- `apple` anonymous attestation, if a device produces it. Consumer iCloud Keychain passkeys do not
  (see `evidence/research-2026-09-16.md` §1); Apple's managed-device passkey attestation produces
  `packed` chained to the *organisation's* CA, which this policy rejects unless that CA is in the
  MDS (it is not) — a deployment for a managed fleet would add an explicit per-tenant anchor.
- `android-key` from a TEE/StrongBox with a Google root. Google Password Manager passkeys are not
  known to produce it (research §2).
- `tpm` from Windows Hello hardware authenticators, **except** that their MDS entry declares
  `matcherProtection: ["software"]`, which the default policy rejects
  (`HV_POLICY_REQUIRE_MATCHER_BEYOND_SOFTWARE=false` to accept). Desktop-only either way.

## User-verification semantics (documented, not assumed)

UV=1 means the authenticator performed *some* user verification: PIN, pattern, or biometric. The
policy records the MDS `userVerificationDetails` methods and `isFreshUserVerificationRequired` as
evidence. Security keys with a PIN cache (CTAP2 `pinUvAuthToken`) may satisfy UV for several
operations after one PIN entry; Apple and Android platform authenticators generally prompt per
operation but may fall back to the device passcode. None of this is "biometric-only", and none of it
is human intent: hardware-only signing, presence, verification and intent are separate properties.

## Signature counters

WebAuthn §6.1.1: a counter of 0 means the authenticator does not implement one. The policy only
treats a non-increasing counter as clone evidence when either the stored or reported value is
non-zero. Synced passkeys always report 0; hardware keys usually increment.

## Backup flags

BE/BS are contextual. A credential with BE=1 can have copies outside the attested hardware, so the
default policy rejects it even when the chain is trusted. They never establish hardware backing
on their own, which is why an untrusted chain with BE=0 is still rejected.

## Known gaps

- CRL checks for MDS/vendor chains rely on the library's `isCertRevoked`, which needs network
  access to the CRL distribution points named in the certificates.
- Attestation-certificate key identifiers (`attestationCertificateKeyIdentifiers`, used by U2F-era
  entries) are not matched; those authenticators cannot carry UV anyway.
- The policy is per-model, not per-device: a compromised individual device that still holds a
  valid attestation key passes.
