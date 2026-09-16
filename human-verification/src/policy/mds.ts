/**
 * FIDO Metadata Service (MDS v3) store.
 *
 * The BLOB is a JWT. Its `x5c` header chain is validated against the GlobalSign roots that the
 * FIDO Alliance publishes for the MDS (pinned copies ship with @simplewebauthn/server and are
 * fingerprint-checked in `trustStore.ts`). Verification is delegated to the library's
 * `verifyMDSBlob`; this module keeps the full payload entries (including `statusReports`, which the
 * library's own MetadataService drops when statements are loaded locally) and tracks freshness.
 */
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { MetadataService, type MetadataBLOBPayloadEntry } from '@simplewebauthn/server';
import { verifyMDSBlob } from '@simplewebauthn/server/helpers';
import type { MdsConfig } from '../config.js';
import type { Logger } from '../logger.js';

export type MdsSource = 'url' | 'file' | 'fixture' | 'none';

export interface MdsSummary {
  source: MdsSource;
  url: string | null;
  serial: number | null;
  nextUpdate: string | null;
  loadedAt: string | null;
  entryCount: number;
  stale: boolean;
  /** Whether the library's own MetadataService was initialised with these statements. */
  libraryInitialised: boolean;
}

export class MetadataStore {
  private entries = new Map<string, MetadataBLOBPayloadEntry>();
  serial: number | null = null;
  nextUpdate: Date | null = null;
  loadedAt: Date | null = null;
  source: MdsSource = 'none';
  url: string | null = null;
  libraryInitialised = false;

  static empty(): MetadataStore {
    return new MetadataStore();
  }

  /** Verify a BLOB (JWT) and load its entries. Throws if the BLOB does not verify. */
  static async fromBlob(blob: string, source: MdsSource, opts: { url?: string; now?: Date } = {}): Promise<MetadataStore> {
    const store = new MetadataStore();
    await store.load(blob, source, opts);
    return store;
  }

  async load(blob: string, source: MdsSource, opts: { url?: string; now?: Date } = {}): Promise<void> {
    const { payload, parsedNextUpdate } = await verifyMDSBlob(blob.trim());
    if (this.serial !== null && payload.no <= this.serial) {
      throw new Error(`MDS BLOB serial ${payload.no} is not newer than loaded serial ${this.serial}`);
    }
    const next = new Map<string, MetadataBLOBPayloadEntry>();
    for (const entry of payload.entries) {
      if (entry.aaguid) next.set(entry.aaguid.toLowerCase(), entry);
    }
    this.entries = next;
    this.serial = payload.no;
    this.nextUpdate = parsedNextUpdate;
    this.loadedAt = opts.now ?? new Date();
    this.source = source;
    this.url = opts.url ?? null;
    // Also give the library the statements so its format verifiers cross-check algorithms and
    // x5c against metadata roots when an AAGUID is known. Permissive mode: strictness is enforced
    // by our policy layer, which needs to see *why* something failed rather than a thrown error.
    const statements = [...next.values()].flatMap((e) => (e.metadataStatement ? [e.metadataStatement] : []));
    await MetadataService.initialize({ statements, verificationMode: 'permissive' });
    this.libraryInitialised = true;
  }

  get(aaguid: string): MetadataBLOBPayloadEntry | undefined {
    return this.entries.get(aaguid.toLowerCase());
  }

  get size(): number {
    return this.entries.size;
  }

  isStale(now: Date = new Date()): boolean {
    if (this.source === 'none') return true;
    if (!this.nextUpdate) return true;
    return now.getTime() > this.nextUpdate.getTime();
  }

  summary(now: Date = new Date()): MdsSummary {
    return {
      source: this.source,
      url: this.url,
      serial: this.serial,
      nextUpdate: this.nextUpdate ? this.nextUpdate.toISOString() : null,
      loadedAt: this.loadedAt ? this.loadedAt.toISOString() : null,
      entryCount: this.entries.size,
      stale: this.isStale(now),
      libraryInitialised: this.libraryInitialised,
    };
  }
}

export type FetchLike = (url: string) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

/**
 * Load the MDS from a cached file and/or the network according to config. Never throws: a
 * deployment without metadata simply rejects every MDS-backed attestation (fail closed).
 */
export async function loadMetadataStore(
  cfg: MdsConfig,
  log: Logger,
  fetchImpl: FetchLike = (u) => fetch(u),
): Promise<MetadataStore> {
  const store = MetadataStore.empty();
  if (cfg.blobPath) {
    try {
      const blob = await readFile(cfg.blobPath, 'utf8');
      await store.load(blob, 'file');
      log.info('mds: loaded cached BLOB from file', { path: cfg.blobPath, serial: store.serial, nextUpdate: store.nextUpdate });
    } catch (err) {
      log.warn('mds: no usable cached BLOB', { path: cfg.blobPath, error: String((err as Error).message ?? err) });
    }
  }
  if (cfg.fetch && (store.source === 'none' || store.isStale())) {
    try {
      const res = await fetchImpl(cfg.url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.text();
      await store.load(blob, 'url', { url: cfg.url });
      log.info('mds: downloaded and verified BLOB', { url: cfg.url, serial: store.serial, nextUpdate: store.nextUpdate });
      if (cfg.blobPath) {
        try {
          await mkdir(dirname(cfg.blobPath), { recursive: true });
          await writeFile(cfg.blobPath, blob, 'utf8');
        } catch (err) {
          log.warn('mds: could not cache BLOB to disk', { error: String((err as Error).message ?? err) });
        }
      }
    } catch (err) {
      log.warn('mds: download failed; MDS-backed attestation formats will be rejected until a BLOB is available', {
        url: cfg.url,
        error: String((err as Error).message ?? err),
      });
    }
  }
  if (store.source === 'none') {
    log.warn('mds: no metadata loaded. Strict policy will reject packed/tpm attestations (fail closed).');
  }
  return store;
}
