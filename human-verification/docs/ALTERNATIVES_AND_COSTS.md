# Alternatives note (not implemented; requires a new scope decision)

If the device matrix confirms that ordinary phone passkeys return `none` attestation, the premise
"trustworthy attestation from ordinary phone authenticators without an app" fails. Options,
none of which this prototype implements:

1. **Browser liveness plus abuse controls.** Drop the hardware-provenance claim. Keep a WebAuthn
   assertion with UV as a *cost signal* (a real user gesture on a real device, unattested) and
   combine it with rate limits, velocity rules, reputation, and honeypots. Cheap and universal; it
   is an interaction-cost mechanism, not a proof of anything. It must not be marketed as
   "hardware-verified".
2. **Apple Private Access Tokens as an additional signal.** RFC 9576–9578 Privacy Pass with Apple
   as attester: proves "valid Apple device and account in good standing" without identity or fresh
   gesture, for Safari/iOS 16+/macOS Ventura+ only. Serve `WWW-Authenticate: PrivateToken` and
   verify with the issuer key. Useful to skip friction for a subset of clients; it says nothing
   about a separately submitted passkey and must never be used to label one "hardware-attested".
3. **Native-app design.** An installed app can use Android Play Integrity and iOS App Attest /
   DeviceCheck to obtain device- and app-integrity signals with vendor-signed verdicts, and can
   hold device-bound keys. This contradicts the no-install requirement and shifts the product to an
   "approve with our app" model.
4. **Restricted-audience product** (from `DECISION.md`): hardware security keys, Windows Hello
   hardware, and MDM-managed Apple fleets with DDM passkey attestation. The verification path built
   here already supports the first two classes once a live MDS is available, and the third with a
   per-tenant anchor.

## Cost notes for the alternatives

- (1) adds no third-party cost; engineering cost is in abuse tooling.
- (2) adds no fee; requires TLS termination that can issue 401 challenges and an issuer-key cache.
- (3) adds app store presence, Play Integrity quota considerations, and App Attest/DeviceCheck
  server integration; per-request costs are not fixed by vendors but quotas apply.
- (4) keeps this codebase; costs are MDS hygiene and tenant onboarding.
