/**
 * WebAuthn ceremonies bound to verification sessions.
 *
 * Two lanes share this code path:
 *   strict      – bound to a verification session; a trusted assertion approves the session.
 *   diagnostic  – no session, no approval, full evidence returned for the device matrix.
 * The lane is part of the challenge binding and of the credential record, so a diagnostic
 * credential or challenge can never be used in the strict lane.
 */
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { decodeClientDataJSON, generateChallenge, isoBase64URL } from '@simplewebauthn/server/helpers';
import { randomBytes } from 'node:crypto';
import type { AppConfig } from '../config.js';
import type { Lane, CredentialRow } from '../db.js';
import { evaluateAttestationPolicy, type PolicyResult } from '../policy/attestationPolicy.js';
import type { MetadataStore } from '../policy/mds.js';
import type { TrustStore } from '../policy/trustStore.js';
import type { SessionService } from './sessions.js';
import type { CredentialService } from './credentials.js';
import type { Logger } from '../logger.js';

export type Hint = 'hybrid' | 'client-device' | 'security-key';
const ALLOWED_HINTS: Hint[] = ['hybrid', 'client-device', 'security-key'];

export interface RegistrationVerdict {
  libraryVerified: boolean;
  libraryError: string | null;
  policy: PolicyResult | null;
  credentialId: string | null;
  stored: boolean;
  challengeError: string | null;
}

export interface AuthenticationVerdict {
  verified: boolean;
  error: string | null;
  credentialId: string | null;
  credentialPolicyTrusted: boolean;
  credentialPolicyVersion: string | null;
  policyVersionCurrent: boolean;
  userVerified: boolean;
  counter: { previous: number; reported: number; checked: boolean; increased: boolean | null } | null;
  backup: { eligible: boolean; state: boolean } | null;
  eligibleForApproval: boolean;
  reasons: string[];
  /** Stored policy verdict for the credential, for display. */
  credentialPolicy: PolicyResult | null;
}

export class WebAuthnService {
  constructor(
    private readonly config: AppConfig,
    private readonly sessions: SessionService,
    private readonly credentials: CredentialService,
    private readonly mds: MetadataStore,
    private readonly trustStore: TrustStore,
    private readonly log: Logger,
    private readonly fetchAndroidRevocationList?: () => Promise<Record<string, { status: string; reason?: string }>>,
  ) {}

  static sanitizeHints(input: unknown): Hint[] {
    if (!Array.isArray(input)) return ['hybrid'];
    const hints = input.filter((h): h is Hint => typeof h === 'string' && (ALLOWED_HINTS as string[]).includes(h));
    return hints.length > 0 ? hints : ['hybrid'];
  }

  /**
   * Registration options. Discoverable credential required: the visitor has no account or username,
   * so returning visits must work with an empty allowCredentials list. Direct attestation and
   * required user verification are the inputs the strict policy needs; the browser is free to
   * downgrade either, which the policy then detects.
   */
  async registrationOptions(opts: { lane: Lane; sessionId: string | null; hints: Hint[] }): Promise<PublicKeyCredentialCreationOptionsJSON & { hints: Hint[] }> {
    const challengeBytes = await generateChallenge();
    const challenge = isoBase64URL.fromBuffer(challengeBytes);
    this.sessions.createChallenge({ sessionId: opts.sessionId, lane: opts.lane, kind: 'registration', ttlSec: this.config.challengeTtlSec, challenge });
    const userID = new Uint8Array(randomBytes(32));
    const shortId = isoBase64URL.fromBuffer(userID.slice(0, 6));
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userName: `visitor-${shortId}`,
      userDisplayName: `Visitor ${shortId}`,
      userID,
      challenge: challengeBytes,
      timeout: this.config.challengeTtlSec * 1000,
      attestationType: 'direct',
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      supportedAlgorithmIDs: [-7, -257],
    });
    return { ...options, hints: opts.hints };
  }

  async verifyRegistration(opts: {
    lane: Lane;
    sessionId: string | null;
    response: RegistrationResponseJSON;
    hints?: Hint[];
  }): Promise<RegistrationVerdict> {
    // 1. Bind to the issued challenge (exact value, session, lane, ceremony), consuming it atomically.
    let challenge: string;
    try {
      const clientData = decodeClientDataJSON(opts.response.response.clientDataJSON);
      challenge = clientData.challenge;
    } catch (err) {
      return { libraryVerified: false, libraryError: null, policy: null, credentialId: null, stored: false, challengeError: `clientDataJSON undecodable: ${(err as Error).message}` };
    }
    const consumed = this.sessions.consumeChallenge({ challenge, sessionId: opts.sessionId, lane: opts.lane, kind: 'registration' });
    if (!consumed.ok) {
      return { libraryVerified: false, libraryError: null, policy: null, credentialId: null, stored: false, challengeError: consumed.reason };
    }

    // 2. Library verification (structure, origin, RP ID, challenge, signature, UV/UP flags).
    let libraryVerified = false;
    let libraryError: string | null = null;
    let registrationInfo: Awaited<ReturnType<typeof verifyRegistrationResponse>>['registrationInfo'] | undefined;
    try {
      const result = await verifyRegistrationResponse({
        response: opts.response,
        expectedChallenge: challenge,
        expectedOrigin: this.config.origin,
        expectedRPID: this.config.rpId,
        requireUserPresence: true,
        requireUserVerification: true,
        supportedAlgorithmIDs: [-7, -257],
      });
      libraryVerified = result.verified;
      registrationInfo = result.registrationInfo;
      if (!result.verified) libraryError = 'library returned verified=false';
    } catch (err) {
      libraryError = (err as Error).message;
    }

    // 3. Independent trust policy evaluation (always runs so diagnostics see the evidence).
    let attestationObject: Uint8Array;
    try {
      attestationObject = isoBase64URL.toBuffer(opts.response.response.attestationObject);
    } catch (err) {
      return { libraryVerified, libraryError: libraryError ?? (err as Error).message, policy: null, credentialId: null, stored: false, challengeError: null };
    }
    const policy = await evaluateAttestationPolicy(
      {
        attestationObject,
        libraryVerified,
        libraryError: libraryError ?? undefined,
        transports: opts.response.response.transports ?? null,
        authenticatorAttachment: opts.response.authenticatorAttachment ?? null,
        credentialDeviceType: registrationInfo?.credentialDeviceType,
        credentialBackedUp: registrationInfo?.credentialBackedUp,
      },
      { config: this.config.policy, trustStore: this.trustStore, mds: this.mds, fetchAndroidRevocationList: this.fetchAndroidRevocationList },
    );

    // 4. Persist only what the library verified. Trust flag is derived from lane + policy.
    if (!libraryVerified || !registrationInfo) {
      return { libraryVerified, libraryError, policy, credentialId: null, stored: false, challengeError: null };
    }
    const existing = this.credentials.get(registrationInfo.credential.id);
    if (existing) {
      return { libraryVerified, libraryError: 'credential ID already enrolled', policy, credentialId: existing.id, stored: false, challengeError: null };
    }
    const userHandle = isoBase64URL.fromBuffer(new Uint8Array(randomBytes(16)));
    this.credentials.store({
      id: registrationInfo.credential.id,
      lane: opts.lane,
      publicKey: registrationInfo.credential.publicKey,
      counter: registrationInfo.credential.counter,
      transports: registrationInfo.credential.transports,
      aaguid: registrationInfo.aaguid,
      fmt: registrationInfo.fmt,
      userHandle,
      backupEligible: registrationInfo.credentialDeviceType === 'multiDevice',
      backupState: registrationInfo.credentialBackedUp,
      uvAtRegistration: registrationInfo.userVerified,
      policy,
      enrolledSessionId: opts.sessionId,
    });
    if (opts.sessionId) this.sessions.noteEnrollment(opts.sessionId, registrationInfo.credential.id);
    this.log.info('registration stored', { lane: opts.lane, credentialId: registrationInfo.credential.id, fmt: registrationInfo.fmt, aaguid: registrationInfo.aaguid, trusted: opts.lane === 'strict' && policy.trusted });
    return { libraryVerified, libraryError, policy, credentialId: registrationInfo.credential.id, stored: true, challengeError: null };
  }

  /** Fresh assertion challenge. Empty allowCredentials: discoverable credentials on the phone. */
  async authenticationOptions(opts: { lane: Lane; sessionId: string | null; hints: Hint[] }): Promise<PublicKeyCredentialRequestOptionsJSON & { hints: Hint[] }> {
    const challengeBytes = await generateChallenge();
    const challenge = isoBase64URL.fromBuffer(challengeBytes);
    this.sessions.createChallenge({ sessionId: opts.sessionId, lane: opts.lane, kind: 'authentication', ttlSec: this.config.challengeTtlSec, challenge });
    const options = await generateAuthenticationOptions({
      rpID: this.config.rpId,
      challenge: challengeBytes,
      timeout: this.config.challengeTtlSec * 1000,
      userVerification: 'required',
      allowCredentials: [],
    });
    return { ...options, hints: opts.hints };
  }

  /**
   * Verifies an assertion and decides eligibility for approval. Approval itself (session state +
   * token) is performed by the caller, and only in the strict lane.
   */
  async verifyAuthentication(opts: { lane: Lane; sessionId: string | null; response: AuthenticationResponseJSON }): Promise<AuthenticationVerdict> {
    const verdict: AuthenticationVerdict = {
      verified: false,
      error: null,
      credentialId: null,
      credentialPolicyTrusted: false,
      credentialPolicyVersion: null,
      policyVersionCurrent: false,
      userVerified: false,
      counter: null,
      backup: null,
      eligibleForApproval: false,
      reasons: [],
      credentialPolicy: null,
    };
    let challenge: string;
    try {
      challenge = decodeClientDataJSON(opts.response.response.clientDataJSON).challenge;
    } catch (err) {
      verdict.error = `clientDataJSON undecodable: ${(err as Error).message}`;
      return verdict;
    }
    const consumed = this.sessions.consumeChallenge({ challenge, sessionId: opts.sessionId, lane: opts.lane, kind: 'authentication' });
    if (!consumed.ok) {
      verdict.error = consumed.reason;
      verdict.reasons.push(consumed.reason);
      return verdict;
    }
    const credential: CredentialRow | undefined = this.credentials.get(opts.response.id);
    if (!credential) {
      verdict.error = 'credential not enrolled with this service';
      verdict.reasons.push(verdict.error);
      return verdict;
    }
    verdict.credentialId = credential.id;
    verdict.credentialPolicyTrusted = credential.policy_trusted === 1;
    verdict.credentialPolicyVersion = credential.policy_version;
    verdict.policyVersionCurrent = credential.policy_version === this.config.policy.version;
    try {
      verdict.credentialPolicy = JSON.parse(credential.policy_result) as PolicyResult;
    } catch {
      verdict.credentialPolicy = null;
    }
    if (credential.lane !== opts.lane) {
      verdict.error = `credential belongs to the ${credential.lane} lane`;
      verdict.reasons.push(verdict.error);
      return verdict;
    }
    try {
      const result = await verifyAuthenticationResponse({
        response: opts.response,
        expectedChallenge: challenge,
        expectedOrigin: this.config.origin,
        expectedRPID: this.config.rpId,
        credential: {
          id: credential.id,
          publicKey: new Uint8Array(credential.public_key),
          counter: credential.counter,
          transports: credential.transports ? (JSON.parse(credential.transports) as string[]) : undefined,
        },
        requireUserVerification: true,
      });
      verdict.verified = result.verified;
      verdict.userVerified = result.authenticationInfo.userVerified;
      verdict.backup = { eligible: result.authenticationInfo.credentialDeviceType === 'multiDevice', state: result.authenticationInfo.credentialBackedUp };
      // Signature counter semantics (WebAuthn §6.1.1): a counter of zero means the authenticator
      // does not implement one (synced passkeys always report 0). Only when either side is non-zero
      // is a non-increasing value evidence of a cloned key. The library already rejects a decrease;
      // we additionally reject "no increase" when a counter was ever seen.
      const previous = credential.counter;
      const reported = result.authenticationInfo.newCounter;
      const checked = previous > 0 || reported > 0;
      const increased = checked ? reported > previous : null;
      verdict.counter = { previous, reported, checked, increased };
      if (checked && !increased) {
        verdict.verified = false;
        verdict.error = 'signature counter did not increase (possible cloned credential)';
        verdict.reasons.push(verdict.error);
        return verdict;
      }
      if (verdict.verified) this.credentials.updateCounter(credential.id, reported);
    } catch (err) {
      verdict.error = (err as Error).message;
      verdict.reasons.push(verdict.error);
      return verdict;
    }
    if (!verdict.verified) {
      verdict.error = verdict.error ?? 'assertion not verified';
      verdict.reasons.push(verdict.error);
      return verdict;
    }
    if (!verdict.credentialPolicyTrusted) verdict.reasons.push('credential did not meet strict attestation policy at enrollment');
    if (!verdict.policyVersionCurrent) verdict.reasons.push(`credential was evaluated under policy ${credential.policy_version}; current is ${this.config.policy.version}`);
    if (credential.lane !== 'strict') verdict.reasons.push('credential is a diagnostic-lane credential');
    verdict.eligibleForApproval = verdict.verified && verdict.credentialPolicyTrusted && verdict.policyVersionCurrent && credential.lane === 'strict' && opts.lane === 'strict';
    return verdict;
  }
}
