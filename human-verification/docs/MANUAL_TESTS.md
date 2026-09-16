# Manual real-device test plan

## Environment

1. Deploy on an HTTPS hostname (see README "Real-device testing over HTTPS"). Use a stable
   hostname: the RP ID must not change between the enrollment and returning-user tests.
2. Enable metadata: `HV_MDS_FETCH=true` and outbound access to `https://mds3.fidoalliance.org/`
   (and CRL/OCSP hosts named in vendor certificates). Confirm on `/policy` that `mds.source` is
   `url`, `stale` is `false`, and `entryCount` is in the hundreds.
3. Keep defaults for the policy. Do **not** set `HV_POLICY_ALLOW_BACKUP_ELIGIBLE` or relax other
   knobs to make a device pass; record the failure instead.
4. Record exact versions: phone model, OS version (Settings → General → About / About phone),
   desktop OS, browser version (`chrome://version`, Safari → About), credential provider (iOS:
   Settings → Passwords → Password Options; Android: Settings → Passwords & accounts).

## Per-row procedure

Use the diagnostics page first (evidence without side effects on sessions), then the demo form for
the end-to-end experience.

### A. Diagnostics (per device, per ceremony)

1. On the desktop browser open `https://<host>/diagnostics`. Fill Device, OS, Browser, Provider,
   Scenario, Bluetooth, Remote, Tester.
2. Select hint `hybrid`. Click **Registration**. Observe and write down: did the browser show its
   own QR / "Use a phone" dialog? Which text? Did the phone prompt for Face ID/Touch ID/fingerprint,
   PIN, or passcode? Did a "save passkey" sheet appear? How long did it take? Any error name/message
   (the page shows `NotAllowedError`, `NotSupportedError`, etc.).
3. Read the verdict table. Copy `fmt`, `aaguid`, chain length and subjects, anchor, UV/BE/BS flags,
   rejection codes. Click **Save evidence row**.
4. Click **Authentication** (fresh assertion with the credential just created). Record UX, flags,
   counter values, `approved: false` (always, in diagnostics). Save the row.
5. Click **Export rows (Markdown)** at the end of the session and paste rows into
   `docs/DEVICE_MATRIX.md`.

### B. Strict flow (demo form)

1. Open `https://<host>/demo/`, submit the form, land on `/verify`.
2. First use: click **Set up a passkey**. Expect the browser's cross-device dialog. Complete it on
   the phone. Read the verdict. If `REJECTED`, this is the result: record it. Do not proceed to
   approval expecting success.
3. If `TRUSTED` (e.g. a security key), click **Approve with an existing passkey**; a fresh
   assertion must be required; the page returns to the site and shows "Submission accepted".
4. Returning use: submit the form again in a new tab; click **Approve with an existing passkey**
   directly; record whether the phone lists the discoverable credential without a username.

### C. Bluetooth-off and remote-phone variants

1. Disable Bluetooth on the phone (then separately on the computer). Repeat A.2. Record the exact
   native error text and whether a fallback is offered. This characterises UI behaviour only; the
   server cannot verify proximity and the matrix must say so.
2. Move the phone out of Bluetooth range (another floor) with Bluetooth on. Repeat A.2. Record
   whether the QR scan proceeds to a Bluetooth failure, a timeout, or success.

### D. Positive control (hardware security key)

1. Use a FIDO2 key with a PIN set (UV required). On the desktop browser select hint
   `security-key`. Run A.2–A.4.
2. Expect `packed` with x5c, chain to the vendor root from the MDS entry, and `TRUSTED` if the
   model's metadata meets policy. If it is `REJECTED` for `METADATA_*`, record the metadata values
   shown; that is a policy decision to review, not a harness bug.
3. This row validates the verification path. It is not phone compatibility.

### E. Negative control

Already automated (`pnpm run test:e2e`). Optionally repeat manually with Chrome DevTools →
WebAuthn → "Enable virtual authenticator environment".

## Recording rules

- Every cell is one of S (server-verified: copied from the verdict), C (client-reported: from the
  "clientReported" block), or M (manually observed). Never promote a C or M value to S.
- Record durations from the page's `ceremonyDurationMs` (C) and wall-clock (M) separately.
- Save the exported JSON (`pnpm run evidence:export`) under `evidence/exports/` and commit it with
  the matrix update; redact nothing except tester names if required.
