/**
 * Test application factory: in-memory database, fixture MDS, programmatic fixture trust anchors.
 * Also exposes a small typed HTTP client over `app.request` and a fixture-authenticator driver
 * that runs complete ceremonies against the API.
 */
import type { Hono } from 'hono';
import { createApp, type AppDeps, type AppEnv } from '../../src/app.js';
import { defaultPolicyConfig, type AppConfig, type PolicyConfig } from '../../src/config.js';
import { openDatabase } from '../../src/db.js';
import { silentLogger } from '../../src/logger.js';
import { MetadataStore } from '../../src/policy/mds.js';
import { createFixtureCA, FixtureCredential, type AttestationShape, type CredentialOptions, type FixtureCA } from './fixtureAuthenticator.js';
import { createFixtureMdsSigner, fixtureMetadataStore, type FixtureBlobOptions, type FixtureMdsSigner } from './fixtureMds.js';

export const TEST_ORIGIN = 'http://localhost:8787';
export const TEST_RP_ID = 'localhost';
export const SITE_A = { id: 'site-a', name: 'Site A', apiKey: 'site-a-key-0123456789' };
export const SITE_B = { id: 'site-b', name: 'Site B', apiKey: 'site-b-key-0123456789' };

export function testConfig(overrides: Partial<AppConfig> = {}, policy: Partial<PolicyConfig> = {}): AppConfig {
  return {
    rpId: TEST_RP_ID,
    rpName: 'Test RP',
    origin: TEST_ORIGIN,
    port: 0,
    dbPath: ':memory:',
    sessionTtlSec: 600,
    challengeTtlSec: 120,
    tokenTtlSec: 120,
    sites: [SITE_A, SITE_B],
    mds: { fetch: false, url: 'https://mds3.fidoalliance.org/' },
    policy: { ...defaultPolicyConfig(), ...policy },
    rateLimits: {
      sessionsPerSite: { max: 10_000, windowSec: 60 },
      sessionsPerIp: { max: 10_000, windowSec: 60 },
      enrollmentsPerIp: { max: 10_000, windowSec: 3600 },
      attemptsPerSession: { max: 10_000, windowSec: 600 },
      approvalsPerCredential: { max: 10_000, windowSec: 3600 },
      redeemsPerSite: { max: 10_000, windowSec: 60 },
      diagnosticsPerIp: { max: 10_000, windowSec: 600 },
    },
    trustProxy: true,
    diagnosticsEnabled: true,
    logLevel: 'error',
    ...overrides,
  };
}

export interface TestHarness {
  app: Hono<AppEnv>;
  deps: AppDeps;
  config: AppConfig;
  ca: FixtureCA;
  unlistedCa: FixtureCA;
  mdsSigner: FixtureMdsSigner;
  mds: MetadataStore;
  http: HttpClient;
}

export interface HarnessOptions {
  config?: Partial<AppConfig>;
  policy?: Partial<PolicyConfig>;
  blob?: Partial<FixtureBlobOptions>;
  /** When false, no MDS is loaded at all (deployment without metadata). */
  withMds?: boolean;
  /** When false, the fixture root is NOT added as a trust anchor even though the MDS lists it. */
  trustFixtureRoot?: boolean;
  androidRevocation?: () => Promise<Record<string, { status: string; reason?: string }>>;
}

export async function createHarness(opts: HarnessOptions = {}): Promise<TestHarness> {
  const ca = await createFixtureCA({ label: 'trusted' });
  const unlistedCa = await createFixtureCA({ label: 'unlisted', aaguid: 'fa57f1c7-0000-4000-8000-0000000000ff' });
  const mdsSigner = await createFixtureMdsSigner();
  const withMds = opts.withMds ?? true;
  const mds = withMds ? await fixtureMetadataStore(mdsSigner, { entries: [{ ca }], ...(opts.blob ?? {}) }) : MetadataStore.empty();
  const trustFixture = opts.trustFixtureRoot ?? true;
  const config = testConfig(opts.config, {
    ...(opts.policy ?? {}),
    ...(trustFixture ? { fixtureTrustAnchors: { label: `fixture attestation CA (${ca.label})`, pems: [ca.rootPem] } } : {}),
  });
  const db = openDatabase(':memory:');
  const { app, deps } = createApp({ config, db, log: silentLogger, mds, fetchAndroidRevocationList: opts.androidRevocation });
  return { app, deps, config, ca, unlistedCa, mdsSigner, mds, http: new HttpClient(app) };
}

export class HttpClient {
  constructor(private readonly app: Hono<AppEnv>, public ip = '203.0.113.10') {}

  async json(path: string, init: { method?: string; body?: unknown; site?: { apiKey: string }; clientToken?: string; headers?: Record<string, string>; rawBody?: string } = {}) {
    const headers: Record<string, string> = { 'content-type': 'application/json', 'x-forwarded-for': this.ip, ...(init.headers ?? {}) };
    if (init.site) headers.authorization = `Bearer ${init.site.apiKey}`;
    if (init.clientToken) headers['x-client-token'] = init.clientToken;
    const res = await this.app.request(path, { method: init.method ?? (init.body !== undefined || init.rawBody !== undefined ? 'POST' : 'GET'), headers, body: init.rawBody ?? (init.body !== undefined ? JSON.stringify(init.body) : undefined) });
    let body: any = null;
    const text = await res.text();
    try { body = JSON.parse(text); } catch { body = text; }
    return { status: res.status, body };
  }
}

export interface SessionHandle {
  id: string;
  clientToken: string;
  action: string;
  digest: string;
  site: typeof SITE_A;
}

export const ACTION = 'contact-form:submit';
export const DIGEST_A = 'a'.repeat(64);
export const DIGEST_B = 'b'.repeat(64);

export async function createSession(h: TestHarness, opts: { site?: typeof SITE_A; action?: string; digest?: string; returnUrl?: string } = {}): Promise<SessionHandle> {
  const site = opts.site ?? SITE_A;
  const action = opts.action ?? ACTION;
  const digest = opts.digest ?? DIGEST_A;
  const res = await h.http.json('/verification-sessions', { site, body: { action, submissionDigest: digest, returnUrl: opts.returnUrl } });
  if (res.status !== 201) throw new Error(`createSession failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { id: res.body.session.id, clientToken: res.body.clientToken, action, digest, site };
}

export interface CeremonyOverrides {
  origin?: string;
  rpId?: string;
  uv?: boolean;
  challengeOverride?: string;
  aaguidInAuthData?: string;
}

/** Runs registration against a session (strict lane). Returns server response + credential. */
export async function enroll(h: TestHarness, s: SessionHandle, shape: AttestationShape, credOpts: Partial<CredentialOptions> = {}, overrides: CeremonyOverrides = {}, cred?: FixtureCredential) {
  const opt = await h.http.json(`/verification-sessions/${s.id}/registration/options`, { clientToken: s.clientToken, body: { hints: ['hybrid'] } });
  if (opt.status !== 200) return { options: opt, verify: null, cred: null as unknown as FixtureCredential };
  const credential = cred ?? (await FixtureCredential.create({ rpId: TEST_RP_ID, origin: TEST_ORIGIN, ...credOpts }));
  const response = await credential.register(opt.body.options, shape, overrides);
  const verify = await h.http.json(`/verification-sessions/${s.id}/registration/verify`, { clientToken: s.clientToken, body: { response } });
  return { options: opt, verify, cred: credential };
}

export async function assertWith(h: TestHarness, s: SessionHandle, cred: FixtureCredential, overrides: Parameters<FixtureCredential['assert']>[1] = {}, opts: { reuseResponse?: unknown } = {}) {
  const opt = await h.http.json(`/verification-sessions/${s.id}/authentication/options`, { clientToken: s.clientToken, body: { hints: ['hybrid'] } });
  if (opt.status !== 200) return { options: opt, verify: null, response: null };
  const response = opts.reuseResponse ?? (await cred.assert(opt.body.options, overrides));
  const verify = await h.http.json(`/verification-sessions/${s.id}/authentication/verify`, { clientToken: s.clientToken, body: { response } });
  return { options: opt, verify, response };
}

export async function redeem(h: TestHarness, s: SessionHandle, token: string, overrides: { site?: typeof SITE_A; sessionId?: string; action?: string; digest?: string } = {}) {
  return h.http.json('/redeem', { site: overrides.site ?? s.site, body: { approvalToken: token, sessionId: overrides.sessionId ?? s.id, action: overrides.action ?? s.action, submissionDigest: overrides.digest ?? s.digest } });
}

export { createFixtureCA, FixtureCredential };
