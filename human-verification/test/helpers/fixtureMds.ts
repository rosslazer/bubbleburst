/**
 * FIXTURE FIDO MDS BLOB — test-only.
 *
 * Builds a metadata BLOB (JWT) signed by a fixture MDS signing chain so that the real
 * `verifyMDSBlob` code path is exercised. The fixture MDS root is installed into the library's
 * SettingsService ONLY by tests that call `installFixtureMdsRoot()`; the deployed service keeps the
 * GlobalSign roots shipped with the library.
 */
import { randomBytes, sign as nodeSign, createPrivateKey, webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { SettingsService, type MetadataBLOBPayloadEntry, type MetadataStatement, type StatusReport } from '@simplewebauthn/server';
import { MetadataStore } from '../../src/policy/mds.js';
import type { FixtureCA } from './fixtureAuthenticator.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export interface FixtureMdsSigner {
  rootPem: string;
  leafDer: Uint8Array;
  rootDer: Uint8Array;
  leafPrivateKeyPkcs8: Buffer;
}

export async function createFixtureMdsSigner(): Promise<FixtureMdsSigner> {
  const root = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const leaf = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const notBefore = new Date(Date.now() - 86_400_000);
  const notAfter = new Date(Date.now() + 365 * 86_400_000);
  const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomBytes(8).toString('hex'),
    name: 'CN=FIXTURE MDS root, O=Fixture Metadata Service, C=US',
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys: root,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true), await x509.SubjectKeyIdentifierExtension.create(root.publicKey)],
  });
  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: randomBytes(8).toString('hex'),
    subject: 'CN=FIXTURE MDS signer, O=Fixture Metadata Service, C=US',
    issuer: rootCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: leaf.publicKey,
    signingKey: root.privateKey,
    extensions: [new x509.BasicConstraintsExtension(false, undefined, true), await x509.AuthorityKeyIdentifierExtension.create(root.publicKey)],
  });
  return {
    rootPem: rootCert.toString('pem'),
    rootDer: new Uint8Array(rootCert.rawData),
    leafDer: new Uint8Array(leafCert.rawData),
    leafPrivateKeyPkcs8: Buffer.from(await webcrypto.subtle.exportKey('pkcs8', leaf.privateKey)),
  };
}

/** Test-only: replaces the library's MDS signing roots with the fixture root. */
export function installFixtureMdsRoot(signer: FixtureMdsSigner): void {
  SettingsService.setRootCertificates({ identifier: 'mds', certificates: [signer.rootPem] });
}

export function fixtureStatement(ca: FixtureCA, overrides: Partial<MetadataStatement> = {}): MetadataStatement {
  return {
    legalHeader: 'FIXTURE metadata statement for tests',
    aaguid: ca.aaguid,
    description: `FIXTURE hardware authenticator (${ca.label})`,
    authenticatorVersion: 1,
    protocolFamily: 'fido2',
    schema: 3,
    upv: [{ major: 1, minor: 0 }],
    authenticationAlgorithms: ['secp256r1_ecdsa_sha256_raw'],
    publicKeyAlgAndEncodings: ['cose'],
    attestationTypes: ['basic_full'],
    userVerificationDetails: [[{ userVerificationMethod: 'passcode_external' }], [{ userVerificationMethod: 'fingerprint_internal' }]],
    keyProtection: ['hardware', 'secure_element'],
    isKeyRestricted: true,
    isFreshUserVerificationRequired: true,
    matcherProtection: ['on_chip'],
    cryptoStrength: 128,
    attachmentHint: ['external', 'wireless', 'bluetooth'],
    tcDisplay: [],
    attestationRootCertificates: [Buffer.from(ca.rootDer).toString('base64')],
    ...overrides,
  };
}

export interface FixtureBlobOptions {
  entries: { ca: FixtureCA; statement?: Partial<MetadataStatement>; statusReports?: StatusReport[]; aaguid?: string }[];
  serial?: number;
  /** YYYY-MM-DD */
  nextUpdate?: string;
}

function b64url(b: Uint8Array | Buffer | string): string {
  return Buffer.from(b).toString('base64url');
}

/** Produces a signed MDS BLOB (JWT, ES256 with DER signature as the library expects). */
export function buildFixtureBlob(signer: FixtureMdsSigner, opts: FixtureBlobOptions): string {
  const future = new Date(Date.now() + 30 * 86_400_000);
  const nextUpdate = opts.nextUpdate ?? future.toISOString().slice(0, 10);
  const entries: MetadataBLOBPayloadEntry[] = opts.entries.map((e) => ({
    aaguid: e.aaguid ?? e.ca.aaguid,
    metadataStatement: fixtureStatement(e.ca, { aaguid: e.aaguid ?? e.ca.aaguid, ...(e.statement ?? {}) }),
    statusReports: e.statusReports ?? [{ status: 'FIDO_CERTIFIED_L1', effectiveDate: '2024-01-01' }],
    timeOfLastStatusChange: '2024-01-01',
  }));
  const header = { alg: 'ES256', typ: 'JWT', x5c: [Buffer.from(signer.leafDer).toString('base64')] }; // the anchor itself is never part of x5c
  const payload = { legalHeader: 'FIXTURE BLOB', no: opts.serial ?? 1, nextUpdate, entries };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const key = createPrivateKey({ key: signer.leafPrivateKeyPkcs8, format: 'der', type: 'pkcs8' });
  // JWS ES256 signatures are raw r||s (IEEE P1363), unlike WebAuthn attestation signatures (DER).
  const sig = nodeSign('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' });
  return `${signingInput}.${b64url(sig)}`;
}

export async function fixtureMetadataStore(signer: FixtureMdsSigner, opts: FixtureBlobOptions): Promise<MetadataStore> {
  installFixtureMdsRoot(signer);
  return MetadataStore.fromBlob(buildFixtureBlob(signer, opts), 'fixture');
}
