/**
 * Runtime configuration for the human-verification prototype.
 *
 * Everything that affects the security boundary is explicit here so that tests can construct
 * the application with a known configuration and so that operators can see what a deployment
 * trusts. Fixture trust anchors can ONLY be supplied programmatically (never from env), which
 * keeps test roots out of any deployed trust store.
 */
import type { AttestationFormat } from '@simplewebauthn/server/helpers';

export interface RateLimitRule {
  max: number;
  windowSec: number;
}

export interface SiteConfig {
  id: string;
  name: string;
  /** Shared secret presented by the site backend as `Authorization: Bearer <apiKey>`. */
  apiKey: string;
}

export interface FixtureTrustAnchors {
  /** Human-readable label that is surfaced in every policy result that relied on this anchor set. */
  label: string;
  /** PEM-encoded root certificates. */
  pems: string[];
}

export interface PolicyConfig {
  version: 'strict-v1';
  /** Attestation formats the strict policy is willing to evaluate at all. */
  allowedFormats: AttestationFormat[];
  /**
   * Whether a credential with the Backup Eligible (BE) flag set may be trusted. Synced passkeys set
   * BE=1; a synced key cannot be hardware-bound in the sense this policy is looking for.
   * Contextual signal only — it never establishes hardware backing by itself.
   */
  allowBackupEligible: boolean;
  /** Require at least one FIDO_CERTIFIED* status report on the MDS entry. */
  requireFidoCertified: boolean;
  /** Reject when the metadata statement lists only `software` matcher protection. */
  requireMatcherProtectionBeyondSoftware: boolean;
  /** Reject all MDS-backed formats when the loaded MDS BLOB is past its `nextUpdate`. */
  rejectWhenMetadataStale: boolean;
  /** Vendor-published roots for formats that are not covered by the FIDO MDS. */
  vendorRoots: {
    apple: boolean;
    androidKey: boolean;
  };
  /** Android key attestation: require the Google attestation revocation list to be consulted. */
  androidKeyRequireRevocationCheck: boolean;
  /** Programmatic-only test fixtures. `loadConfigFromEnv` never sets this. */
  fixtureTrustAnchors?: FixtureTrustAnchors;
}

export interface MdsConfig {
  /** Attempt to download the FIDO MDS BLOB from `url` at startup and when `nextUpdate` passes. */
  fetch: boolean;
  url: string;
  /** Optional path to a previously downloaded BLOB (JWT) used when fetching is disabled or fails. */
  blobPath?: string;
}

export interface AppConfig {
  rpId: string;
  rpName: string;
  /** The single first-party origin that hosts the verification page. */
  origin: string;
  port: number;
  /** better-sqlite3 path, or `:memory:`. */
  dbPath: string;
  sessionTtlSec: number;
  challengeTtlSec: number;
  tokenTtlSec: number;
  sites: SiteConfig[];
  mds: MdsConfig;
  policy: PolicyConfig;
  rateLimits: {
    sessionsPerSite: RateLimitRule;
    sessionsPerIp: RateLimitRule;
    enrollmentsPerIp: RateLimitRule;
    attemptsPerSession: RateLimitRule;
    approvalsPerCredential: RateLimitRule;
    redeemsPerSite: RateLimitRule;
    diagnosticsPerIp: RateLimitRule;
  };
  /** Trust `X-Forwarded-For` for the client IP (set only behind a proxy you control). */
  trustProxy: boolean;
  /** Serve the diagnostic lane. Diagnostic results never produce approval tokens. */
  diagnosticsEnabled: boolean;
  /** Log level. */
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

function envInt(env: NodeJS.ProcessEnv, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) throw new Error(`Invalid integer for ${key}: ${raw}`);
  return n;
}

function envBool(env: NodeJS.ProcessEnv, key: string, fallback: boolean): boolean {
  const raw = env[key];
  if (raw === undefined || raw === '') return fallback;
  return raw === '1' || raw.toLowerCase() === 'true';
}

function rule(env: NodeJS.ProcessEnv, key: string, max: number, windowSec: number): RateLimitRule {
  return { max: envInt(env, `${key}_MAX`, max), windowSec: envInt(env, `${key}_WINDOW_SEC`, windowSec) };
}

export const DEFAULT_DEMO_SITE: SiteConfig = {
  id: 'demo-site',
  name: 'Demo contact form',
  apiKey: 'demo-site-key-change-me',
};

export function defaultPolicyConfig(): PolicyConfig {
  return {
    version: 'strict-v1',
    allowedFormats: ['packed', 'tpm', 'android-key', 'apple'],
    allowBackupEligible: false,
    requireFidoCertified: true,
    requireMatcherProtectionBeyondSoftware: true,
    rejectWhenMetadataStale: true,
    vendorRoots: { apple: true, androidKey: true },
    androidKeyRequireRevocationCheck: true,
  };
}

export function loadConfigFromEnv(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const origin = env.HV_ORIGIN ?? 'http://localhost:8787';
  const rpId = env.HV_RP_ID ?? new URL(origin).hostname;
  let sites: SiteConfig[] = [DEFAULT_DEMO_SITE];
  if (env.HV_SITES_JSON) {
    const parsed = JSON.parse(env.HV_SITES_JSON) as SiteConfig[];
    if (!Array.isArray(parsed) || parsed.some((s) => !s.id || !s.apiKey)) {
      throw new Error('HV_SITES_JSON must be an array of { id, name, apiKey }');
    }
    sites = parsed;
  }
  const policy = defaultPolicyConfig();
  policy.allowBackupEligible = envBool(env, 'HV_POLICY_ALLOW_BACKUP_ELIGIBLE', policy.allowBackupEligible);
  policy.requireFidoCertified = envBool(env, 'HV_POLICY_REQUIRE_FIDO_CERTIFIED', policy.requireFidoCertified);
  policy.requireMatcherProtectionBeyondSoftware = envBool(
    env,
    'HV_POLICY_REQUIRE_MATCHER_BEYOND_SOFTWARE',
    policy.requireMatcherProtectionBeyondSoftware,
  );
  policy.rejectWhenMetadataStale = envBool(env, 'HV_POLICY_REJECT_STALE_MDS', policy.rejectWhenMetadataStale);
  policy.vendorRoots.apple = envBool(env, 'HV_POLICY_VENDOR_ROOT_APPLE', true);
  policy.vendorRoots.androidKey = envBool(env, 'HV_POLICY_VENDOR_ROOT_ANDROID_KEY', true);
  policy.androidKeyRequireRevocationCheck = envBool(env, 'HV_POLICY_ANDROID_KEY_REVOCATION_CHECK', true);

  return {
    rpId,
    rpName: env.HV_RP_NAME ?? 'Human verification prototype',
    origin,
    port: envInt(env, 'HV_PORT', 8787),
    dbPath: env.HV_DB_PATH ?? 'data/hv.sqlite',
    sessionTtlSec: envInt(env, 'HV_SESSION_TTL_SEC', 600),
    challengeTtlSec: envInt(env, 'HV_CHALLENGE_TTL_SEC', 120),
    tokenTtlSec: envInt(env, 'HV_TOKEN_TTL_SEC', 120),
    sites,
    mds: {
      fetch: envBool(env, 'HV_MDS_FETCH', true),
      url: env.HV_MDS_URL ?? 'https://mds3.fidoalliance.org/',
      blobPath: env.HV_MDS_BLOB_PATH ?? 'data/mds-blob.jwt',
    },
    policy,
    rateLimits: {
      sessionsPerSite: rule(env, 'HV_RL_SESSIONS_PER_SITE', 600, 60),
      sessionsPerIp: rule(env, 'HV_RL_SESSIONS_PER_IP', 30, 60),
      enrollmentsPerIp: rule(env, 'HV_RL_ENROLLMENTS_PER_IP', 10, 3600),
      attemptsPerSession: rule(env, 'HV_RL_ATTEMPTS_PER_SESSION', 10, 600),
      approvalsPerCredential: rule(env, 'HV_RL_APPROVALS_PER_CREDENTIAL', 20, 3600),
      redeemsPerSite: rule(env, 'HV_RL_REDEEMS_PER_SITE', 1200, 60),
      diagnosticsPerIp: rule(env, 'HV_RL_DIAGNOSTICS_PER_IP', 60, 600),
    },
    trustProxy: envBool(env, 'HV_TRUST_PROXY', false),
    diagnosticsEnabled: envBool(env, 'HV_DIAGNOSTICS_ENABLED', true),
    logLevel: (env.HV_LOG_LEVEL as AppConfig['logLevel']) ?? 'info',
  };
}
