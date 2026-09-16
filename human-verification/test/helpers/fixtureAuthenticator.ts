/**
 * FIXTURE AUTHENTICATOR — test-only software emulator.
 *
 * Produces WebAuthn registration and authentication responses with a configurable attestation
 * shape so that the strict policy can be exercised deterministically:
 *   - fmt "none"                      (attestation stripped)
 *   - fmt "packed" self-attestation   (no x5c; what a virtual authenticator produces)
 *   - fmt "packed" full attestation   (x5c chained to the FIXTURE attestation CA)
 *   - arbitrary fmt with a fixture chain (e.g. "apple" with the wrong root → unknown root)
 *
 * Keys are generated with WebCrypto/Node crypto; certificates with @peculiar/x509; CBOR with
 * @levischuck/tiny-cbor. Nothing here is hand-rolled cryptography, and nothing here is ever used by
 * the deployed service. The fixture CA root is only trusted when a test passes it in as
 * `policy.fixtureTrustAnchors` (programmatic-only configuration).
 */
import { createHash, createPrivateKey, createPublicKey, KeyObject, randomBytes, sign as nodeSign, webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { encodeCBOR, type CBORType } from '@levischuck/tiny-cbor';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export const FIXTURE_AAGUID = 'fa57f1c7-0000-4000-8000-000000000001';
export const FIXTURE_AAGUID_UNLISTED = 'fa57f1c7-0000-4000-8000-0000000000ff';
const OID_FIDO_GEN_CE_AAGUID = '1.3.6.1.4.1.45724.1.1.4';

export interface FixtureCA {
  label: string;
  rootPem: string;
  rootDer: Uint8Array;
  rootKey: CryptoKey;
  leafPem: string;
  leafDer: Uint8Array;
  leafKey: CryptoKey;
  leafKeyObject: KeyObject;
  aaguid: string;
}

function b64url(bytes: Uint8Array | Buffer | string): string {
  return Buffer.from(bytes).toString('base64url');
}

function aaguidBytes(aaguid: string): Uint8Array {
  return Uint8Array.from(Buffer.from(aaguid.replace(/-/g, ''), 'hex'));
}

async function ecKeyPair(): Promise<CryptoKeyPair> {
  return webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

async function toKeyObject(priv: CryptoKey): Promise<KeyObject> {
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', priv);
  return createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
}

/** Builds a fixture attestation CA (root + attestation leaf). `aaguid` is embedded in the leaf. */
export async function createFixtureCA(opts: { label?: string; aaguid?: string; leafAaguidOverride?: string; leafOu?: string } = {}): Promise<FixtureCA> {
  const label = opts.label ?? 'fixture-attestation-ca';
  const aaguid = opts.aaguid ?? FIXTURE_AAGUID;
  const root = await ecKeyPair();
  const leaf = await ecKeyPair();
  const notBefore = new Date(Date.now() - 86_400_000);
  const notAfter = new Date(Date.now() + 365 * 86_400_000);
  const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomBytes(8).toString('hex'),
    name: `CN=FIXTURE ${label} root, O=Fixture Authenticator Co, C=US`,
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys: root,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true), await x509.SubjectKeyIdentifierExtension.create(root.publicKey)],
  });
  const leafAaguid = opts.leafAaguidOverride ?? aaguid;
  const extValue = Buffer.concat([Buffer.from([0x04, 0x10]), Buffer.from(aaguidBytes(leafAaguid))]);
  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: randomBytes(8).toString('hex'),
    subject: `CN=FIXTURE ${label} attestation, OU=${opts.leafOu ?? 'Authenticator Attestation'}, O=Fixture Authenticator Co, C=US`,
    issuer: rootCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: leaf.publicKey,
    signingKey: root.privateKey,
    extensions: [new x509.BasicConstraintsExtension(false, undefined, true), new x509.Extension(OID_FIDO_GEN_CE_AAGUID, false, extValue), await x509.AuthorityKeyIdentifierExtension.create(root.publicKey)],
  });
  return {
    label,
    rootPem: rootCert.toString('pem'),
    rootDer: new Uint8Array(rootCert.rawData),
    rootKey: root.privateKey,
    leafPem: leafCert.toString('pem'),
    leafDer: new Uint8Array(leafCert.rawData),
    leafKey: leaf.privateKey,
    leafKeyObject: await toKeyObject(leaf.privateKey),
    aaguid,
  };
}

export type AttestationShape =
  | { kind: 'none' }
  | { kind: 'self' }
  | { kind: 'full'; ca: FixtureCA; fmt?: string; extraChain?: Uint8Array[]; malformedStatement?: boolean };

export interface CredentialOptions {
  rpId: string;
  origin: string;
  aaguid?: string;
  uv?: boolean;
  up?: boolean;
  be?: boolean;
  bs?: boolean;
  counter?: number;
  transports?: string[];
  authenticatorAttachment?: 'platform' | 'cross-platform';
}

export class FixtureCredential {
  readonly id: Uint8Array;
  readonly idB64: string;
  counter: number;
  constructor(readonly keys: CryptoKeyPair, readonly keyObject: KeyObject, readonly opts: CredentialOptions) {
    this.id = new Uint8Array(randomBytes(32));
    this.idB64 = b64url(this.id);
    this.counter = opts.counter ?? 0;
  }

  static async create(opts: CredentialOptions): Promise<FixtureCredential> {
    const keys = await ecKeyPair();
    return new FixtureCredential(keys, await toKeyObject(keys.privateKey), opts);
  }

  private async cosePublicKey(): Promise<Uint8Array> {
    const jwk = await webcrypto.subtle.exportKey('jwk', this.keys.publicKey);
    const x = Buffer.from(jwk.x!, 'base64url');
    const y = Buffer.from(jwk.y!, 'base64url');
    const map = new Map<number, CBORType>([[1, 2], [3, -7], [-1, 1], [-2, new Uint8Array(x)], [-3, new Uint8Array(y)]]);
    return encodeCBOR(map);
  }

  private flags(o: { at: boolean; uvOverride?: boolean; upOverride?: boolean }): number {
    let f = 0;
    if (o.upOverride ?? this.opts.up ?? true) f |= 0x01;
    if (o.uvOverride ?? this.opts.uv ?? true) f |= 0x04;
    if (this.opts.be) f |= 0x08;
    if (this.opts.bs) f |= 0x10;
    if (o.at) f |= 0x40;
    return f;
  }

  private rpIdHash(rpId = this.opts.rpId): Uint8Array {
    return new Uint8Array(createHash('sha256').update(rpId).digest());
  }

  private counterBytes(): Uint8Array {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(this.counter >>> 0);
    return new Uint8Array(b);
  }

  private clientData(type: 'webauthn.create' | 'webauthn.get', challenge: string, origin = this.opts.origin): Uint8Array {
    return new Uint8Array(Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false })));
  }

  /** Builds a registration response for the given options (as returned by the server). */
  async register(
    options: { challenge: string; rp?: { id?: string } },
    shape: AttestationShape,
    overrides: { origin?: string; rpId?: string; uv?: boolean; up?: boolean; challengeOverride?: string; aaguidInAuthData?: string } = {},
  ): Promise<RegistrationResponseJSON> {
    const aaguid = overrides.aaguidInAuthData ?? this.opts.aaguid ?? (shape.kind === 'full' ? shape.ca.aaguid : '00000000-0000-0000-0000-000000000000');
    const cose = await this.cosePublicKey();
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.id.length);
    const authData = Buffer.concat([
      Buffer.from(this.rpIdHash(overrides.rpId)),
      Buffer.from([this.flags({ at: true, uvOverride: overrides.uv, upOverride: overrides.up })]),
      Buffer.from(this.counterBytes()),
      Buffer.from(aaguidBytes(aaguid)),
      idLen,
      Buffer.from(this.id),
      Buffer.from(cose),
    ]);
    const clientDataJSON = this.clientData('webauthn.create', overrides.challengeOverride ?? options.challenge, overrides.origin);
    const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
    const signedData = Buffer.concat([authData, clientDataHash]);
    let fmt = 'none';
    let attStmt: Map<string, CBORType> = new Map();
    if (shape.kind === 'self') {
      fmt = 'packed';
      attStmt = new Map<string, CBORType>([['alg', -7], ['sig', new Uint8Array(nodeSign('sha256', signedData, this.keyObject))]]);
    } else if (shape.kind === 'full') {
      fmt = shape.fmt ?? 'packed';
      const sig = new Uint8Array(nodeSign('sha256', signedData, shape.ca.leafKeyObject));
      const x5c = [shape.ca.leafDer, ...(shape.extraChain ?? [])];
      attStmt = shape.malformedStatement ? new Map<string, CBORType>([['alg', -7], ['x5c', x5c as CBORType]]) : new Map<string, CBORType>([['alg', -7], ['sig', sig], ['x5c', x5c as CBORType]]);
    }
    const attestationObject = encodeCBOR(new Map<string, CBORType>([['fmt', fmt], ['attStmt', attStmt], ['authData', new Uint8Array(authData)]]));
    return {
      id: this.idB64,
      rawId: this.idB64,
      type: 'public-key',
      response: { clientDataJSON: b64url(clientDataJSON), attestationObject: b64url(attestationObject), transports: this.opts.transports ?? ['hybrid', 'internal'] },
      clientExtensionResults: {},
      authenticatorAttachment: this.opts.authenticatorAttachment ?? 'cross-platform',
    };
  }

  /** Builds an assertion. Increments the counter unless `counterOverride` is given. */
  async assert(
    options: { challenge: string },
    overrides: { origin?: string; rpId?: string; uv?: boolean; up?: boolean; challengeOverride?: string; counterOverride?: number; corruptSignature?: boolean; signWith?: KeyObject } = {},
  ): Promise<AuthenticationResponseJSON> {
    if (overrides.counterOverride !== undefined) this.counter = overrides.counterOverride;
    else if (this.counter > 0) this.counter += 1;
    const authData = Buffer.concat([Buffer.from(this.rpIdHash(overrides.rpId)), Buffer.from([this.flags({ at: false, uvOverride: overrides.uv, upOverride: overrides.up })]), Buffer.from(this.counterBytes())]);
    const clientDataJSON = this.clientData('webauthn.get', overrides.challengeOverride ?? options.challenge, overrides.origin);
    const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
    let sig = nodeSign('sha256', Buffer.concat([authData, clientDataHash]), overrides.signWith ?? this.keyObject);
    if (overrides.corruptSignature) sig = Buffer.from(nodeSign('sha256', Buffer.concat([authData, clientDataHash, Buffer.from('x')]), this.keyObject));
    return {
      id: this.idB64,
      rawId: this.idB64,
      type: 'public-key',
      response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(sig), userHandle: undefined },
      clientExtensionResults: {},
      authenticatorAttachment: this.opts.authenticatorAttachment ?? 'cross-platform',
    };
  }
}

export { createPublicKey };
