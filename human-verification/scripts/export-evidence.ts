/**
 * Exports sanitized evidence from a running or offline database:
 *   - policy/trust-store summary
 *   - diagnostic runs (server-verified / client-reported / manually-observed, labelled)
 *   - credentials table without public keys (AAGUID, fmt, policy outcome, flags)
 * Usage: HV_DB_PATH=data/hv.sqlite pnpm run evidence:export [outDir]
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfigFromEnv } from '../src/config.js';
import { openDatabase, type CredentialRow, type DiagnosticRunRow } from '../src/db.js';
import { MetadataStore, loadMetadataStore } from '../src/policy/mds.js';
import { TrustStore } from '../src/policy/trustStore.js';
import { createLogger } from '../src/logger.js';

const config = loadConfigFromEnv();
const outDir = process.argv[2] ?? 'evidence/exports';
mkdirSync(outDir, { recursive: true });
const db = openDatabase(config.dbPath);
const mds = config.mds.fetch || config.mds.blobPath ? await loadMetadataStore({ ...config.mds, fetch: false }, createLogger('warn')) : MetadataStore.empty();
const trust = new TrustStore(config.policy, mds);

const runs = (db.prepare('SELECT * FROM diagnostic_runs ORDER BY created_at').all() as DiagnosticRunRow[]).map((r) => ({ id: r.id, createdAt: new Date(r.created_at).toISOString(), kind: r.kind, ...(JSON.parse(r.evidence) as object) }));
const creds = (db.prepare('SELECT * FROM credentials ORDER BY created_at').all() as CredentialRow[]).map((c) => {
  const policy = JSON.parse(c.policy_result) as { outcome: string; rejectionCodes: string[]; evidence: { chain: unknown; metadata: unknown } };
  return { lane: c.lane, aaguid: c.aaguid, fmt: c.fmt, backupEligible: !!c.backup_eligible, backupState: !!c.backup_state, uvAtRegistration: !!c.uv_at_registration, policyTrusted: !!c.policy_trusted, policyVersion: c.policy_version, outcome: policy.outcome, rejectionCodes: policy.rejectionCodes, chain: policy.evidence.chain, metadata: policy.evidence.metadata, transportsClientReported: c.transports ? JSON.parse(c.transports) : null, createdAt: new Date(c.created_at).toISOString() };
});
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const bundle = { exportedAt: new Date().toISOString(), rpId: config.rpId, origin: config.origin, policy: { ...config.policy, fixtureTrustAnchors: undefined }, mds: mds.summary(), trustAnchors: trust.summary(), diagnosticRuns: runs, credentials: creds };
const file = join(outDir, `evidence-${stamp}.json`);
writeFileSync(file, JSON.stringify(bundle, null, 2));
console.log(`wrote ${file}: ${runs.length} diagnostic runs, ${creds.length} credentials`);
