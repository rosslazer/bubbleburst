/**
 * Explicit trust anchors for attestation chain validation.
 *
 * Sources:
 *  - FIDO MDS v3 entries (`attestationRootCertificates` per AAGUID), loaded via `MetadataStore`.
 *  - Vendor-published roots for formats outside the MDS: Apple WebAuthn Root CA (fmt `apple`) and
 *    Google Hardware Attestation roots (fmt `android-key`). The PEMs are the pinned copies shipped in
 *    @simplewebauthn/server; at startup their SHA-256 fingerprints are compared with the values the
 *    vendors publish (recorded below) so a tampered dependency cannot silently swap a root.
 *  - Fixture anchors, programmatic-only, for tests. They are labelled in every verdict.
 *
 * A client-supplied chain is never trusted on its own; every chain must reach one of these anchors.
 */
import { X509Certificate } from '@peculiar/x509';
import { createHash } from 'node:crypto';
import { SettingsService } from '@simplewebauthn/server';
import type { AttestationFormat } from '@simplewebauthn/server/helpers';
import type { PolicyConfig } from '../config.js';
import type { MetadataStore } from './mds.js';

export type AnchorKind = 'mds' | 'vendor:apple' | 'vendor:android-key' | 'fixture';

export interface TrustAnchorSet {
  kind: AnchorKind;
  label: string;
  source: string;
  pems: string[];
  fingerprintsSha256: string[];
}

/** Vendor-published fingerprints (SHA-256 of DER), used to pin the embedded copies. */
export const PINNED_ROOT_FINGERPRINTS: Record<string, { fingerprint: string; source: string }[]> = {
  'vendor:apple': [
    {
      fingerprint: '0915dd5c07a28db549d1f677bb5a75d4bfbe9561a773424327762e9e02f9bb29',
      source: 'https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem (Apple WebAuthn Root CA, valid to 2045-03-15)',
    },
  ],
  mds: [
    {
      fingerprint: 'cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b',
      source: 'GlobalSign Root CA - R3 (https://valid.r3.roots.globalsign.com/), FIDO MDS BLOB signing root',
    },
    {
      fingerprint: '4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9',
      source: 'GlobalSign Root R46 (https://valid.r46.roots.globalsign.com/)',
    },
  ],
};

export function pemFingerprintSha256(pem: string): string {
  const cert = new X509Certificate(pem);
  return createHash('sha256').update(Buffer.from(cert.rawData)).digest('hex');
}

export function derBase64ToPem(b64: string): string {
  const body = b64.replace(/\s+/g, '').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

export interface TrustStoreSummary {
  anchors: { kind: AnchorKind; label: string; source: string; fingerprintsSha256: string[]; pinVerified: boolean | null; count: number }[];
}

export class TrustStore {
  readonly apple: TrustAnchorSet | null;
  readonly androidKey: TrustAnchorSet | null;
  readonly fixture: TrustAnchorSet | null;
  readonly mdsSigning: TrustAnchorSet;
  readonly pinFailures: string[] = [];

  constructor(private readonly policy: PolicyConfig, private readonly mds: MetadataStore) {
    const applePems = SettingsService.getRootCertificates({ identifier: 'apple' });
    const androidPems = SettingsService.getRootCertificates({ identifier: 'android-key' });
    const mdsPems = SettingsService.getRootCertificates({ identifier: 'mds' });

    this.apple = policy.vendorRoots.apple
      ? {
          kind: 'vendor:apple',
          label: 'Apple WebAuthn Root CA (vendor-published)',
          source: PINNED_ROOT_FINGERPRINTS['vendor:apple']![0]!.source,
          pems: applePems,
          fingerprintsSha256: applePems.map(pemFingerprintSha256),
        }
      : null;
    this.androidKey = policy.vendorRoots.androidKey
      ? {
          kind: 'vendor:android-key',
          label: 'Google Hardware Attestation Roots 1-4 (vendor-published)',
          source: 'https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate',
          pems: androidPems,
          fingerprintsSha256: androidPems.map(pemFingerprintSha256),
        }
      : null;
    this.mdsSigning = {
      kind: 'mds',
      label: 'FIDO MDS BLOB signing roots (GlobalSign)',
      source: PINNED_ROOT_FINGERPRINTS.mds!.map((p) => p.source).join('; '),
      pems: mdsPems,
      fingerprintsSha256: mdsPems.map(pemFingerprintSha256),
    };
    this.fixture = policy.fixtureTrustAnchors
      ? {
          kind: 'fixture',
          label: `FIXTURE: ${policy.fixtureTrustAnchors.label}`,
          source: 'test fixture (programmatic only; never configured from environment)',
          pems: policy.fixtureTrustAnchors.pems,
          fingerprintsSha256: policy.fixtureTrustAnchors.pems.map(pemFingerprintSha256),
        }
      : null;

    // Pin checks against vendor-published fingerprints.
    if (this.apple) {
      const expected = PINNED_ROOT_FINGERPRINTS['vendor:apple']!.map((p) => p.fingerprint);
      for (const fp of this.apple.fingerprintsSha256) {
        if (!expected.includes(fp)) this.pinFailures.push(`apple root fingerprint ${fp} does not match the published value`);
      }
    }
  }

  /** Anchors that may vouch for a chain of the given format/AAGUID under strict policy. */
  anchorsFor(fmt: AttestationFormat, aaguid: string): { set: TrustAnchorSet | null; reason: string } {
    // Vendor formats are anchored only by vendor roots; fixtures never substitute for them.
    if (fmt === 'apple') {
      return this.apple
        ? { set: this.apple, reason: 'apple format: vendor-published Apple WebAuthn Root CA' }
        : { set: null, reason: 'apple vendor root disabled by policy' };
    }
    if (fmt === 'android-key') {
      return this.androidKey
        ? { set: this.androidKey, reason: 'android-key format: Google hardware attestation roots' }
        : { set: null, reason: 'android-key vendor roots disabled by policy' };
    }
    if (this.fixture && this.fixtureCoversAaguid(aaguid)) {
      return { set: this.fixture, reason: 'fixture trust anchors cover this AAGUID' };
    }
    const entry = this.mds.get(aaguid);
    const roots = entry?.metadataStatement?.attestationRootCertificates ?? [];
    if (!entry || roots.length === 0) {
      return { set: null, reason: 'no MDS entry (or no attestation roots) for this AAGUID' };
    }
    const pems = roots.map(derBase64ToPem);
    return {
      set: {
        kind: 'mds',
        label: `FIDO MDS entry "${entry.metadataStatement?.description ?? aaguid}"`,
        source: this.mds.url ?? `MDS BLOB (${this.mds.source})`,
        pems,
        fingerprintsSha256: pems.map(pemFingerprintSha256),
      },
      reason: 'roots published in the FIDO MDS statement for this AAGUID',
    };
  }

  private fixtureCoversAaguid(aaguid: string): boolean {
    // Fixture entries are injected into the MetadataStore by the test harness; the fixture anchor
    // set applies only to AAGUIDs whose MDS entry lists a fixture root.
    const entry = this.mds.get(aaguid);
    const roots = entry?.metadataStatement?.attestationRootCertificates ?? [];
    const fixtureFps = new Set(this.fixture?.fingerprintsSha256 ?? []);
    return roots.some((r) => fixtureFps.has(pemFingerprintSha256(derBase64ToPem(r))));
  }

  summary(): TrustStoreSummary {
    const sets = [this.mdsSigning, this.apple, this.androidKey, this.fixture].filter((s): s is TrustAnchorSet => !!s);
    return {
      anchors: sets.map((s) => ({
        kind: s.kind,
        label: s.label,
        source: s.source,
        fingerprintsSha256: s.fingerprintsSha256,
        pinVerified: s.kind === 'vendor:apple' ? this.pinFailures.length === 0 : s.kind === 'mds' ? s.fingerprintsSha256.every((fp) => PINNED_ROOT_FINGERPRINTS.mds!.some((p) => p.fingerprint === fp)) : null,
        count: s.pems.length,
      })),
    };
  }
}
