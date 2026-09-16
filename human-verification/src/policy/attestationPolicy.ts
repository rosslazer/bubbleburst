/**
 * Strict attestation trust policy (version `strict-v1`).
 *
 * The WebAuthn library answers "is this registration response well-formed and internally
 * consistent?". This layer answers a different question: "does independently trusted evidence
 * establish that the private key lives in an authenticator whose security properties we accept?"
 *
 * Every verdict carries the list of checks that produced it, each labelled with its basis:
 *   server-verified  – cryptographically or structurally checked by this server
 *   documented       – taken from vendor/FIDO metadata (trusted publisher, not the client)
 *   client-reported  – supplied by the browser/client; contextual only, never security evidence
 *
 * Fails closed: anything unexpected is a rejection with a code, never a pass.
 */
import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { KeyDescription, id_ce_keyDescription } from '@peculiar/asn1-android';
import { X509Certificate } from '@peculiar/x509';
import type { AuthenticatorStatus, MetadataBLOBPayloadEntry } from '@simplewebauthn/server';
import {
  convertCertBufferToPEM,
  decodeAttestationObject,
  parseAuthenticatorData,
  validateCertificatePath,
  type AttestationFormat,
  type AttestationStatement,
} from '@simplewebauthn/server/helpers';
import type { PolicyConfig } from '../config.js';
import type { MetadataStore } from './mds.js';
import type { AnchorKind, TrustStore } from './trustStore.js';

export type CheckResult = 'pass' | 'fail' | 'skip' | 'info';
export type Basis = 'server-verified' | 'documented' | 'client-reported';

export interface PolicyCheck {
  id: string;
  result: CheckResult;
  basis: Basis;
  detail: string;
}

export type RejectionCode =
  | 'LIBRARY_VERIFICATION_FAILED'
  | 'ATTESTATION_ABSENT'
  | 'SELF_ATTESTATION'
  | 'FORMAT_NOT_ALLOWED'
  | 'UNSUPPORTED_EVIDENCE'
  | 'METADATA_UNAVAILABLE'
  | 'METADATA_STALE'
  | 'AAGUID_NOT_IN_METADATA'
  | 'METADATA_STATUS_UNACCEPTABLE'
  | 'METADATA_NOT_CERTIFIED'
  | 'METADATA_NO_FULL_ATTESTATION'
  | 'METADATA_KEY_PROTECTION_UNACCEPTABLE'
  | 'METADATA_MATCHER_PROTECTION_UNACCEPTABLE'
  | 'METADATA_NO_UV_METHOD'
  | 'CHAIN_ABSENT'
  | 'CHAIN_INVALID'
  | 'NO_TRUST_ANCHOR'
  | 'AAGUID_MISMATCH'
  | 'ANDROID_SECURITY_LEVEL_UNACCEPTABLE'
  | 'ANDROID_REVOCATION_UNAVAILABLE'
  | 'ANDROID_CERT_REVOKED'
  | 'USER_VERIFICATION_MISSING'
  | 'BACKUP_ELIGIBLE_NOT_HARDWARE_BOUND'
  | 'MALFORMED_ATTESTATION';

export interface PolicyEvidence {
  fmt: string;
  aaguid: string;
  attestationType: 'none' | 'self' | 'basic_full' | 'anonca' | 'android-key' | 'unknown';
  chain: {
    present: boolean;
    length: number;
    leafSubject: string | null;
    subjects: string[];
    anchorKind: AnchorKind | null;
    anchorLabel: string | null;
    valid: boolean;
  };
  metadata: {
    source: string | null;
    description: string | null;
    statuses: AuthenticatorStatus[];
    keyProtection: string[];
    matcherProtection: string[];
    attestationTypes: string[];
    userVerificationMethods: string[];
    isFreshUserVerificationRequired: boolean | null;
    hardwareKeyProtectionEstablished: boolean;
    enforcedUserVerificationEstablished: boolean;
  };
  flags: { up: boolean; uv: boolean; be: boolean; bs: boolean };
  contextual: {
    credentialDeviceType: string;
    credentialBackedUp: boolean;
    transportsClientReported: string[] | null;
    authenticatorAttachmentClientReported: string | null;
  };
  androidKey?: { attestationSecurityLevel: number; keymasterSecurityLevel: number } | null;
}

export interface PolicyResult {
  policyVersion: PolicyConfig['version'];
  trusted: boolean;
  outcome: 'TRUSTED' | 'REJECTED';
  rejectionCodes: RejectionCode[];
  checks: PolicyCheck[];
  evidence: PolicyEvidence;
  evaluatedAt: string;
}

export interface PolicyInput {
  /** Raw CBOR attestation object bytes from the registration response. */
  attestationObject: Uint8Array;
  /** Result of the library's `verifyRegistrationResponse` (or the thrown error). */
  libraryVerified: boolean;
  libraryError?: string;
  /** Client-reported values; contextual only. */
  transports?: string[] | null;
  authenticatorAttachment?: string | null;
  credentialDeviceType?: string;
  credentialBackedUp?: boolean;
}

export interface PolicyContext {
  config: PolicyConfig;
  trustStore: TrustStore;
  mds: MetadataStore;
  now?: Date;
  /** Fetches the Google attestation revocation list. Injected for tests. */
  fetchAndroidRevocationList?: () => Promise<Record<string, { status: string; reason?: string }>>;
}

const COMPROMISE_STATUSES: AuthenticatorStatus[] = [
  'REVOKED',
  'USER_VERIFICATION_BYPASS',
  'ATTESTATION_KEY_COMPROMISE',
  'USER_KEY_REMOTE_COMPROMISE',
  'USER_KEY_PHYSICAL_COMPROMISE',
];

const ID_FIDO_GEN_CE_AAGUID = '1.3.6.1.4.1.45724.1.1.4';

/** Android `SecurityLevel` enum values (KeyMint attestation schema). */
const ANDROID_SECURITY_LEVEL = { Software: 0, TrustedEnvironment: 1, StrongBox: 2 } as const;

function subjectString(pem: string): string {
  try {
    return new X509Certificate(pem).subject;
  } catch {
    return '<unparseable>';
  }
}

function leafAaguidFromCert(der: Uint8Array): string | null {
  const cert = AsnParser.parse(der, Certificate);
  const ext = cert.tbsCertificate.extensions?.find((e) => e.extnID === ID_FIDO_GEN_CE_AAGUID);
  if (!ext) return null;
  // extnValue is an OCTET STRING wrapping an OCTET STRING of 16 bytes: 04 10 <aaguid>
  const bytes = new Uint8Array(ext.extnValue.buffer);
  if (bytes.length !== 18 || bytes[0] !== 0x04 || bytes[1] !== 0x10) return '<malformed>';
  const hex = Buffer.from(bytes.subarray(2)).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function uvMethods(entry: MetadataBLOBPayloadEntry | undefined): string[] {
  const details = entry?.metadataStatement?.userVerificationDetails ?? [];
  const methods = new Set<string>();
  for (const combo of details) for (const d of combo) methods.add(d.userVerificationMethod);
  return [...methods];
}

/** True when at least one AND-combination in the statement enforces something beyond presence. */
function hasEnforcedUvMethod(entry: MetadataBLOBPayloadEntry | undefined): boolean {
  const details = entry?.metadataStatement?.userVerificationDetails ?? [];
  return details.some((combo) => combo.length > 0 && combo.every((d) => d.userVerificationMethod !== 'none' && d.userVerificationMethod !== 'presence_internal'));
}

export async function evaluateAttestationPolicy(input: PolicyInput, ctx: PolicyContext): Promise<PolicyResult> {
  const now = ctx.now ?? new Date();
  const checks: PolicyCheck[] = [];
  const codes = new Set<RejectionCode>();
  const add = (id: string, result: CheckResult, basis: Basis, detail: string, code?: RejectionCode) => {
    checks.push({ id, result, basis, detail });
    if (result === 'fail' && code) codes.add(code);
  };

  const evidence: PolicyEvidence = {
    fmt: 'unknown',
    aaguid: '',
    attestationType: 'unknown',
    chain: { present: false, length: 0, leafSubject: null, subjects: [], anchorKind: null, anchorLabel: null, valid: false },
    metadata: {
      source: null,
      description: null,
      statuses: [],
      keyProtection: [],
      matcherProtection: [],
      attestationTypes: [],
      userVerificationMethods: [],
      isFreshUserVerificationRequired: null,
      hardwareKeyProtectionEstablished: false,
      enforcedUserVerificationEstablished: false,
    },
    flags: { up: false, uv: false, be: false, bs: false },
    contextual: {
      credentialDeviceType: input.credentialDeviceType ?? 'unknown',
      credentialBackedUp: input.credentialBackedUp ?? false,
      transportsClientReported: input.transports ?? null,
      authenticatorAttachmentClientReported: input.authenticatorAttachment ?? null,
    },
    androidKey: null,
  };

  const finish = (): PolicyResult => {
    const trusted = codes.size === 0 && checks.some((c) => c.id === 'chain.valid' && c.result === 'pass');
    if (!trusted && codes.size === 0) codes.add('UNSUPPORTED_EVIDENCE');
    return {
      policyVersion: ctx.config.version,
      trusted,
      outcome: trusted ? 'TRUSTED' : 'REJECTED',
      rejectionCodes: [...codes],
      checks,
      evidence,
      evaluatedAt: now.toISOString(),
    };
  };

  // 0. Library verification is a precondition, not a verdict.
  if (input.libraryVerified) {
    add('library.verified', 'pass', 'server-verified', 'WebAuthn library accepted the registration response (challenge, origin, RP ID, signature, structure).');
  } else {
    add('library.verified', 'fail', 'server-verified', `WebAuthn library rejected the response: ${input.libraryError ?? 'unknown error'}`, 'LIBRARY_VERIFICATION_FAILED');
  }

  // 1. Decode the attestation object ourselves so evidence is available even when the library failed.
  let fmt: AttestationFormat;
  let attStmt: AttestationStatement;
  let aaguid = '';
  try {
    const decoded = decodeAttestationObject(input.attestationObject as Uint8Array<ArrayBuffer>);
    fmt = decoded.get('fmt');
    attStmt = decoded.get('attStmt');
    const authData = parseAuthenticatorData(decoded.get('authData'));
    evidence.flags = { up: authData.flags.up, uv: authData.flags.uv, be: authData.flags.be, bs: authData.flags.bs };
    if (authData.aaguid) {
      const hex = Buffer.from(authData.aaguid).toString('hex');
      aaguid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }
  } catch (err) {
    add('attestation.decode', 'fail', 'server-verified', `Attestation object could not be decoded: ${(err as Error).message}`, 'MALFORMED_ATTESTATION');
    return finish();
  }
  evidence.fmt = fmt;
  evidence.aaguid = aaguid;
  add('attestation.decode', 'pass', 'server-verified', `Attestation format "${fmt}", AAGUID ${aaguid || '(none)'}.`);

  // 2. User verification flag at registration.
  if (evidence.flags.uv) {
    add('flags.uv', 'pass', 'server-verified', 'UV flag set in authenticator data (method unknown: PIN, pattern or biometric are all valid UV).');
  } else {
    add('flags.uv', 'fail', 'server-verified', 'UV flag not set; strict policy requires user verification at enrollment.', 'USER_VERIFICATION_MISSING');
  }

  // 3. Format gate.
  if (fmt === 'none') {
    evidence.attestationType = 'none';
    add('attestation.present', 'fail', 'server-verified', 'Attestation format "none": the authenticator or client stripped attestation. No provenance evidence.', 'ATTESTATION_ABSENT');
    recordBackupFlags();
    return finish();
  }
  if (!ctx.config.allowedFormats.includes(fmt)) {
    add('attestation.format', 'fail', 'server-verified', `Format "${fmt}" is not accepted by strict policy (${ctx.config.allowedFormats.join(', ')}).`, fmt === 'android-safetynet' || fmt === 'fido-u2f' ? 'UNSUPPORTED_EVIDENCE' : 'FORMAT_NOT_ALLOWED');
    recordBackupFlags();
    return finish();
  }
  add('attestation.format', 'pass', 'server-verified', `Format "${fmt}" is evaluable under strict policy.`);

  // 4. Chain presence.
  const x5c = attStmt.get('x5c') as Uint8Array<ArrayBuffer>[] | undefined;
  if (!x5c || x5c.length === 0) {
    if (fmt === 'packed') {
      evidence.attestationType = 'self';
      add('chain.present', 'fail', 'server-verified', 'Packed self-attestation (no x5c): signed by the credential key itself. Any software can produce this.', 'SELF_ATTESTATION');
    } else {
      add('chain.present', 'fail', 'server-verified', `Format "${fmt}" without an x5c chain cannot be tied to a trust anchor.`, 'CHAIN_ABSENT');
    }
    recordBackupFlags();
    return finish();
  }
  const x5cPem = x5c.map(convertCertBufferToPEM);
  evidence.chain.present = true;
  evidence.chain.length = x5c.length;
  evidence.chain.subjects = x5cPem.map(subjectString);
  evidence.chain.leafSubject = evidence.chain.subjects[0] ?? null;
  evidence.attestationType = fmt === 'apple' ? 'anonca' : fmt === 'android-key' ? 'android-key' : 'basic_full';
  add('chain.present', 'pass', 'server-verified', `x5c chain with ${x5c.length} certificate(s); leaf subject: ${evidence.chain.leafSubject}.`);

  // 5. Resolve trust anchors.
  const anchors = ctx.trustStore.anchorsFor(fmt, aaguid);
  const mdsBacked = fmt === 'packed' || fmt === 'tpm';
  const entry = mdsBacked ? ctx.mds.get(aaguid) : undefined;

  if (mdsBacked) {
    if (ctx.mds.source === 'none') {
      add('metadata.available', 'fail', 'documented', 'No FIDO MDS BLOB is loaded; MDS-backed formats fail closed.', 'METADATA_UNAVAILABLE');
    } else if (ctx.config.rejectWhenMetadataStale && ctx.mds.isStale(now)) {
      add('metadata.fresh', 'fail', 'documented', `MDS BLOB serial ${ctx.mds.serial} is past nextUpdate ${ctx.mds.nextUpdate?.toISOString()}; policy rejects stale metadata.`, 'METADATA_STALE');
    } else {
      add('metadata.fresh', 'pass', 'documented', `MDS BLOB serial ${ctx.mds.serial} (${ctx.mds.source}) valid until ${ctx.mds.nextUpdate?.toISOString()}.`);
    }
    if (!entry) {
      add('metadata.entry', 'fail', 'documented', `AAGUID ${aaguid} has no entry in the loaded MDS BLOB.`, 'AAGUID_NOT_IN_METADATA');
    } else {
      const ms = entry.metadataStatement;
      evidence.metadata.source = ctx.mds.url ?? `MDS BLOB (${ctx.mds.source})`;
      evidence.metadata.description = ms?.description ?? null;
      evidence.metadata.statuses = entry.statusReports.map((r) => r.status);
      evidence.metadata.keyProtection = ms?.keyProtection ?? [];
      evidence.metadata.matcherProtection = ms?.matcherProtection ?? [];
      evidence.metadata.attestationTypes = ms?.attestationTypes ?? [];
      evidence.metadata.userVerificationMethods = uvMethods(entry);
      evidence.metadata.isFreshUserVerificationRequired = ms?.isFreshUserVerificationRequired ?? null;
      add('metadata.entry', 'pass', 'documented', `MDS entry found: "${ms?.description ?? aaguid}" (last status change ${entry.timeOfLastStatusChange}).`);

      const compromised = entry.statusReports.filter((r) => COMPROMISE_STATUSES.includes(r.status));
      if (compromised.length > 0) {
        add('metadata.status', 'fail', 'documented', `Status report(s) ${compromised.map((r) => r.status).join(', ')} present; authenticator model is revoked/compromised.`, 'METADATA_STATUS_UNACCEPTABLE');
      } else {
        add('metadata.status', 'pass', 'documented', `No compromise/revocation status. Statuses: ${evidence.metadata.statuses.join(', ') || '(none)'}.`);
      }
      const certified = entry.statusReports.some((r) => r.status.startsWith('FIDO_CERTIFIED'));
      if (ctx.config.requireFidoCertified && !certified) {
        add('metadata.certified', 'fail', 'documented', 'No FIDO_CERTIFIED* status report; policy requires certification.', 'METADATA_NOT_CERTIFIED');
      } else {
        add('metadata.certified', certified ? 'pass' : 'info', 'documented', certified ? 'FIDO certification status present.' : 'Not FIDO certified (policy does not require it).');
      }
      // basic_full: chain to the vendor attestation CA. attca: chain to an attestation/privacy CA (TPM).
      // Both tie the key to an attested authenticator model; surrogate/none/ecdaa do not.
      const fullTypes = (ms?.attestationTypes ?? []).filter((t) => t === 'basic_full' || t === 'attca');
      if (fullTypes.length === 0) {
        add('metadata.attestationTypes', 'fail', 'documented', `Metadata attestation types ${JSON.stringify(ms?.attestationTypes ?? [])} include neither basic_full nor attca.`, 'METADATA_NO_FULL_ATTESTATION');
      } else {
        add('metadata.attestationTypes', 'pass', 'documented', `Metadata declares ${fullTypes.join('/')} attestation.`);
      }
      const kp = ms?.keyProtection ?? [];
      const hwKey = kp.includes('hardware') && !kp.includes('software') && !kp.includes('remote_handle') && (kp.includes('secure_element') || kp.includes('tee'));
      evidence.metadata.hardwareKeyProtectionEstablished = hwKey;
      if (!hwKey) {
        add('metadata.keyProtection', 'fail', 'documented', `keyProtection ${JSON.stringify(kp)} does not establish hardware (SE/TEE) key protection.`, 'METADATA_KEY_PROTECTION_UNACCEPTABLE');
      } else {
        add('metadata.keyProtection', 'pass', 'documented', `keyProtection ${JSON.stringify(kp)}.`);
      }
      const mp = ms?.matcherProtection ?? [];
      const mpOk = mp.some((m) => m === 'tee' || m === 'on_chip');
      if (ctx.config.requireMatcherProtectionBeyondSoftware && !mpOk) {
        add('metadata.matcherProtection', 'fail', 'documented', `matcherProtection ${JSON.stringify(mp)} is software-only; UV enforcement not hardware-backed.`, 'METADATA_MATCHER_PROTECTION_UNACCEPTABLE');
      } else {
        add('metadata.matcherProtection', mpOk ? 'pass' : 'info', 'documented', `matcherProtection ${JSON.stringify(mp)}.`);
      }
      const uvOk = hasEnforcedUvMethod(entry);
      evidence.metadata.enforcedUserVerificationEstablished = uvOk && mpOk;
      if (!uvOk) {
        add('metadata.userVerification', 'fail', 'documented', `userVerificationDetails ${JSON.stringify(evidence.metadata.userVerificationMethods)} offer no method beyond presence.`, 'METADATA_NO_UV_METHOD');
      } else {
        add('metadata.userVerification', 'pass', 'documented', `UV methods: ${evidence.metadata.userVerificationMethods.join(', ')}. isFreshUserVerificationRequired=${String(ms?.isFreshUserVerificationRequired ?? 'unspecified')}.`);
      }
    }
  }

  // 6. AAGUID consistency between authenticator data and leaf certificate (packed/tpm).
  if (mdsBacked) {
    try {
      const certAaguid = leafAaguidFromCert(x5c[0]!);
      if (certAaguid === null) {
        add('chain.aaguidExtension', 'info', 'server-verified', 'Leaf certificate carries no id-fido-gen-ce-aaguid extension.');
      } else if (certAaguid !== aaguid) {
        add('chain.aaguidExtension', 'fail', 'server-verified', `Leaf certificate AAGUID ${certAaguid} does not match authenticator data AAGUID ${aaguid}.`, 'AAGUID_MISMATCH');
      } else {
        add('chain.aaguidExtension', 'pass', 'server-verified', 'Leaf certificate AAGUID extension matches authenticator data.');
      }
    } catch (err) {
      add('chain.aaguidExtension', 'fail', 'server-verified', `Leaf certificate unparseable: ${(err as Error).message}`, 'MALFORMED_ATTESTATION');
    }
  }

  // 7. Chain validation against explicit anchors (independent of the library).
  if (!anchors.set || anchors.set.pems.length === 0) {
    add('chain.anchor', 'fail', 'server-verified', `No trust anchor: ${anchors.reason}.`, 'NO_TRUST_ANCHOR');
  } else {
    evidence.chain.anchorKind = anchors.set.kind;
    evidence.chain.anchorLabel = anchors.set.label;
    add('chain.anchor', 'pass', anchors.set.kind === 'fixture' ? 'server-verified' : 'documented', `Anchor set: ${anchors.set.label} (${anchors.reason}).`);
    try {
      await validateCertificatePath(x5cPem, anchors.set.pems);
      evidence.chain.valid = true;
      add('chain.valid', 'pass', 'server-verified', `Certificate path validates to ${anchors.set.label}.`);
    } catch (err) {
      add('chain.valid', 'fail', 'server-verified', `Certificate path does not reach the trust anchor: ${(err as Error).message}`, 'CHAIN_INVALID');
    }
  }

  // 8. Format-specific hardware evidence.
  if (fmt === 'apple') {
    evidence.metadata.source = 'vendor documentation (Apple Platform Security Guide): keys attested by the Apple WebAuthn CA are Secure Enclave-backed';
    evidence.metadata.keyProtection = ['hardware', 'secure_element'];
    evidence.metadata.hardwareKeyProtectionEstablished = evidence.chain.valid && input.libraryVerified;
    evidence.metadata.enforcedUserVerificationEstablished = evidence.flags.uv && evidence.chain.valid;
    add('apple.nonce', input.libraryVerified ? 'pass' : 'fail', 'server-verified', input.libraryVerified ? 'Library verified the Apple nonce extension binds the certificate to this authenticator data.' : 'Apple nonce/key binding not verified.', input.libraryVerified ? undefined : 'LIBRARY_VERIFICATION_FAILED');
  }
  if (fmt === 'android-key') {
    try {
      const cert = AsnParser.parse(x5c[0]!, Certificate);
      const ext = cert.tbsCertificate.extensions?.find((e) => e.extnID === id_ce_keyDescription);
      if (!ext) throw new Error('KeyDescription extension missing');
      const kd = AsnParser.parse(ext.extnValue, KeyDescription);
      const att = Number(kd.attestationSecurityLevel);
      const km = Number(kd.keymasterSecurityLevel);
      evidence.androidKey = { attestationSecurityLevel: att, keymasterSecurityLevel: km };
      const ok = att >= ANDROID_SECURITY_LEVEL.TrustedEnvironment && km >= ANDROID_SECURITY_LEVEL.TrustedEnvironment;
      evidence.metadata.source = 'Android Key Attestation extension (security levels) + Google hardware attestation roots';
      evidence.metadata.keyProtection = ok ? ['hardware', km === ANDROID_SECURITY_LEVEL.StrongBox ? 'secure_element' : 'tee'] : ['software'];
      evidence.metadata.hardwareKeyProtectionEstablished = ok && evidence.chain.valid;
      add('android.securityLevel', ok ? 'pass' : 'fail', 'server-verified', `attestationSecurityLevel=${att}, keymasterSecurityLevel=${km} (0=Software, 1=TEE, 2=StrongBox).`, ok ? undefined : 'ANDROID_SECURITY_LEVEL_UNACCEPTABLE');
    } catch (err) {
      add('android.securityLevel', 'fail', 'server-verified', `KeyDescription extension unusable: ${(err as Error).message}`, 'MALFORMED_ATTESTATION');
    }
    if (ctx.config.androidKeyRequireRevocationCheck) {
      if (!ctx.fetchAndroidRevocationList) {
        add('android.revocation', 'fail', 'documented', 'Google attestation revocation list not consulted (no fetcher configured); fail closed.', 'ANDROID_REVOCATION_UNAVAILABLE');
      } else {
        try {
          const list = await ctx.fetchAndroidRevocationList();
          const serials = x5cPem.map((p) => new X509Certificate(p).serialNumber.replace(/^0+/, '').toLowerCase());
          const hit = serials.find((s) => list[s]);
          if (hit) {
            add('android.revocation', 'fail', 'documented', `Certificate serial ${hit} is listed as ${list[hit]!.status} (${list[hit]!.reason ?? 'no reason'}).`, 'ANDROID_CERT_REVOKED');
          } else {
            add('android.revocation', 'pass', 'documented', `No chain serial appears in the Google attestation status list (${Object.keys(list).length} entries).`);
          }
        } catch (err) {
          add('android.revocation', 'fail', 'documented', `Revocation list unavailable: ${(err as Error).message}; fail closed.`, 'ANDROID_REVOCATION_UNAVAILABLE');
        }
      }
    } else {
      add('android.revocation', 'info', 'documented', 'Revocation check disabled by configuration.');
    }
  }

  recordBackupFlags();
  return finish();

  function recordBackupFlags() {
    const { be, bs } = evidence.flags;
    if (be && !ctx.config.allowBackupEligible) {
      add('flags.backupEligible', 'fail', 'server-verified', `BE=1 (BS=${bs ? 1 : 0}): credential is eligible for backup/sync, so a copy may exist outside the attested hardware. Contextual signal; policy treats it as disqualifying.`, 'BACKUP_ELIGIBLE_NOT_HARDWARE_BOUND');
    } else {
      add('flags.backupEligible', 'info', 'server-verified', `BE=${be ? 1 : 0}, BS=${bs ? 1 : 0}. Backup flags are contextual and never establish hardware backing on their own.`);
    }
    add('contextual.transports', 'info', 'client-reported', `transports=${JSON.stringify(input.transports ?? null)}, attachment=${input.authenticatorAttachment ?? 'null'}. Client-reported; not security evidence and does not indicate which transport was used for any assertion.`);
  }
}
