# Real-device compatibility matrix

Field labels: **S** = server-verified (from the policy verdict / library), **C** = client-reported
(browser-supplied, unsigned), **M** = manually observed by the tester. Rows are filled from the
diagnostics page (`/diagnostics` → "Save evidence row" → "Export rows") and `pnpm run evidence:export`.

No device results are invented. Rows without a device in this environment are UNTESTED.

| # | Device / OS (M) | Desktop browser (M) | Provider (M) | Ceremony | fmt (S) | Chain to trusted root (S) | Metadata source (S) | UV flag (S) | BE/BS (S) | Transports (C) | Observed UX (M) | Duration (C) | Policy outcome (S) | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | iPhone, iOS ≥ 17 | Chrome (macOS/Windows), exact version | iCloud Keychain (AAGUID fbfc3007-154e-4ecc-8c0b-6e020557d7bd) | cross-device enrollment | expected `none` (research §1) | — | — | — | expected BE=1/BS=1 | — | — | — | expected `REJECTED: ATTESTATION_ABSENT` | **UNTESTED** |
| 2 | iPhone, iOS ≥ 17 | Chrome | iCloud Keychain | cross-device authentication | n/a (assertions carry no attestation) | uses stored verdict | — | — | — | — | — | — | not eligible if row 1 rejected | **UNTESTED** |
| 3 | iPhone, iOS ≥ 17 | Safari (macOS), exact version | iCloud Keychain | enrollment + authentication | expected `none` | — | — | — | — | — | note: Safari ignores `hints` | — | expected `REJECTED` | **UNTESTED** |
| 4 | Android 14/15 phone | Chrome (Windows/macOS/Linux), exact version | Google Password Manager (AAGUID ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4) | cross-device enrollment | expected `none` (research §2) | — | — | — | expected BE=1 | — | — | — | expected `REJECTED: ATTESTATION_ABSENT` | **UNTESTED** |
| 5 | Android 14/15 phone | Chrome | Google Password Manager | cross-device authentication | n/a | uses stored verdict | — | — | — | — | — | — | not eligible if row 4 rejected | **UNTESTED** |
| 6 | Phone as in 1/4 | Chrome | as above | Bluetooth **off** on phone or computer | — | — | — | — | — | — | characterise native UI failure text; not a proximity proof | — | — | **UNTESTED** |
| 7 | Phone as in 1/4 | Chrome | as above | phone physically remote (other room/building), Bluetooth on | — | — | — | — | — | — | characterise whether the hybrid flow completes or errors | — | — | **UNTESTED** |
| 8 | Windows 11 desktop | Edge/Chrome | Windows Hello | enrollment + authentication (platform, not phone) | expected `tpm` (research §3) | expected Microsoft TPM root via MDS | MDS | — | BE=0 | — | — | — | expected `REJECTED: METADATA_MATCHER_PROTECTION_UNACCEPTABLE` under defaults | **UNTESTED** |
| 9 | Desktop Firefox, exact version | Firefox | any | enrollment | — | — | — | — | — | — | Firefox ignores `hints`; record which UI appears | — | — | **UNTESTED** |
| 10 | Hardware security key (e.g. YubiKey 5 series, FIDO2, PIN set) — **positive control, does not count as phone compatibility** | Chrome/Safari/Firefox | none (roaming) | enrollment + authentication over USB/NFC | expected `packed` with x5c | expected chain to vendor root via **live MDS** | MDS (needs `HV_MDS_FETCH=true` and egress) | expected UV=1 with PIN | BE=0 | `usb`/`nfc` | — | — | expected `TRUSTED` if the model is FIDO-certified and metadata meets policy | **UNTESTED** (no key, no MDS egress here) |
| 11 | Software authenticator (Chromium 141.0.7390.37 CDP virtual authenticator, ctap2_1, UV on, RK on) — **negative control** | Headless Chromium 141.0.7390.37, Playwright 1.56.1 | virtual | enrollment | `packed`, 1-cert chain "C=US, O=Chromium, OU=Authenticator Attestation, CN=Batch Certificate", AAGUID 01020304-0506-0708-0102-030405060708 | no (no anchor) | none loaded in this run | UV=1 | BE=0/BS=0 (row 11a) and BE=1/BS=1 (row 11b) | `["internal"]`, attachment `platform` | automatic presence, no dialogs (headless) | 15 ms (client) | `REJECTED: AAGUID_NOT_IN_METADATA, NO_TRUST_ANCHOR, METADATA_UNAVAILABLE` (+ `BACKUP_ELIGIBLE_NOT_HARDWARE_BOUND` for 11b) | **TESTED 2026-09-16** |
| 12 | Same as 11 | same | virtual | authentication | n/a | stored verdict REJECTED | — | UV=1 | as enrolled | `["internal"]` | — | — | verified=true, approved=false, token=null | **TESTED 2026-09-16** |
| 13 | FIXTURE authenticator (test-only software emulator with a labelled fixture CA and fixture MDS entry) — **positive control of the verification path only; not hardware** | API tests (no browser) | fixture | enrollment + authentication | `packed` with x5c to `FIXTURE` root | yes, anchor `FIXTURE: fixture attestation CA` | fixture MDS BLOB | UV=1 | BE=0 | `["hybrid","internal"]` (synthetic) | n/a | n/a | `TRUSTED` → token → redeemed once | **TESTED 2026-09-16** |

Reference for expected values: `evidence/research-2026-09-16.md`. The "expected" cells are
hypotheses to be confirmed or refuted, not results.
