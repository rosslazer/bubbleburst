/**
 * Application assembly: dependencies, auth middleware, routes, static pages.
 */
import { Hono, type Context, type MiddlewareHandler } from 'hono';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { normalize, extname, resolve, sep } from 'node:path';
import type { AppConfig, SiteConfig } from './config.js';
import type { DB, SessionRow } from './db.js';
import { openDatabase } from './db.js';
import { constantTimeEqual } from './ids.js';
import { createLogger, type Logger } from './logger.js';
import { MetadataStore } from './policy/mds.js';
import { TrustStore } from './policy/trustStore.js';
import { RateLimiter } from './ratelimit.js';
import { CredentialService } from './services/credentials.js';
import { SessionService } from './services/sessions.js';
import { WebAuthnService } from './services/webauthnService.js';
import { verificationRoutes } from './routes/verification.js';
import { diagnosticsRoutes } from './routes/diagnostics.js';
import { demoSiteRoutes, type VerificationApiClient } from './demo-site/routes.js';

export type AppEnv = { Variables: { site: SiteConfig; session: SessionRow } };

export interface AppDeps {
  config: AppConfig;
  db: DB;
  log: Logger;
  mds: MetadataStore;
  trustStore: TrustStore;
  sessions: SessionService;
  credentials: CredentialService;
  webauthn: WebAuthnService;
  rateLimiter: RateLimiter;
  clientIp: (c: Context<AppEnv>) => string;
  siteFromAuth: (authorization: string | undefined) => SiteConfig | null;
  requireSite: MiddlewareHandler<AppEnv>;
  requireClient: MiddlewareHandler<AppEnv>;
}

export interface CreateAppOptions {
  config: AppConfig;
  db?: DB;
  log?: Logger;
  mds?: MetadataStore;
  fetchAndroidRevocationList?: () => Promise<Record<string, { status: string; reason?: string }>>;
}

const PUBLIC_DIR = fileURLToPath(new URL('../public/', import.meta.url));
const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
};

export function createApp(opts: CreateAppOptions): { app: Hono<AppEnv>; deps: AppDeps } {
  const config = opts.config;
  const log = opts.log ?? createLogger(config.logLevel);
  const db = opts.db ?? openDatabase(config.dbPath);
  const mds = opts.mds ?? MetadataStore.empty();
  const trustStore = new TrustStore(config.policy, mds);
  if (trustStore.pinFailures.length > 0) {
    throw new Error(`Trust store pin failure: ${trustStore.pinFailures.join('; ')}`);
  }
  const sessions = new SessionService(db);
  const credentials = new CredentialService(db);
  const rateLimiter = new RateLimiter(db);
  const androidRevocation =
    opts.fetchAndroidRevocationList ??
    (async () => {
      const res = await fetch('https://android.googleapis.com/attestation/status', { headers: { 'cache-control': 'no-cache' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = (await res.json()) as { entries?: Record<string, { status: string; reason?: string }> };
      return json.entries ?? {};
    });
  const webauthn = new WebAuthnService(config, sessions, credentials, mds, trustStore, log, androidRevocation);

  const siteFromAuth = (authorization: string | undefined): SiteConfig | null => {
    if (!authorization) return null;
    const m = /^Bearer\s+(.+)$/i.exec(authorization.trim());
    if (!m) return null;
    const key = m[1]!;
    for (const site of config.sites) {
      if (constantTimeEqual(site.apiKey, key)) return site;
    }
    return null;
  };

  const clientIp = (c: Context<AppEnv>): string => {
    if (config.trustProxy) {
      const xff = c.req.header('x-forwarded-for');
      if (xff) return xff.split(',')[0]!.trim();
    }
    const direct = c.req.header('x-hv-conn-ip');
    return direct ?? '0.0.0.0';
  };

  const requireSite: MiddlewareHandler<AppEnv> = async (c, next) => {
    const site = siteFromAuth(c.req.header('authorization'));
    if (!site) return c.json({ error: 'unauthorized' }, 401);
    c.set('site', site);
    await next();
  };

  const requireClient: MiddlewareHandler<AppEnv> = async (c, next) => {
    // CSRF: JSON body + custom header + Origin check. Cross-site form posts cannot satisfy these.
    const origin = c.req.header('origin');
    if (origin && origin !== config.origin) return c.json({ error: 'bad_origin' }, 403);
    const ct = c.req.header('content-type') ?? '';
    if (c.req.method === 'POST' && !ct.toLowerCase().startsWith('application/json')) return c.json({ error: 'json_required' }, 415);
    const id = c.req.param('id');
    const session = id ? sessions.get(id) : undefined;
    if (!session) return c.json({ error: 'not_found' }, 404);
    if (!sessions.clientAuthorized(session, c.req.header('x-client-token'))) return c.json({ error: 'forbidden' }, 403);
    c.set('session', session);
    await next();
  };

  const deps: AppDeps = { config, db, log, mds, trustStore, sessions, credentials, webauthn, rateLimiter, clientIp, siteFromAuth, requireSite, requireClient };

  const app = new Hono<AppEnv>();

  app.use('*', async (c, next) => {
    await next();
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('Referrer-Policy', 'no-referrer');
    c.header('Cache-Control', c.req.path.startsWith('/static/') || c.req.path.startsWith('/vendor/') ? 'public, max-age=300' : 'no-store');
  });

  app.get('/healthz', (c) => c.json({ ok: true, rpId: config.rpId, origin: config.origin }));

  app.get('/policy', (c) =>
    c.json({
      policy: { ...config.policy, fixtureTrustAnchors: config.policy.fixtureTrustAnchors ? { label: config.policy.fixtureTrustAnchors.label, count: config.policy.fixtureTrustAnchors.pems.length } : null },
      mds: mds.summary(),
      trustAnchors: trustStore.summary(),
      rpId: config.rpId,
      origin: config.origin,
      diagnosticsEnabled: config.diagnosticsEnabled,
      claims: {
        provides: 'Assertion from a credential whose enrollment evidence met the configured authenticator policy, bound to one site/action/submission.',
        doesNotProvide: ['proof of a unique human', 'proof of Bluetooth proximity or of which transport was used', 'proof that a biometric (rather than PIN/pattern) was used', 'resistance to paid human solvers using accepted authenticators'],
      },
    }),
  );

  app.route('/', verificationRoutes(deps));
  app.route('/diagnostics', diagnosticsRoutes(deps));

  // Demo relying site. Talks to the verification API over the HTTP contract (in-process dispatch).
  const demoSite = config.sites[0]!;
  const client: VerificationApiClient = {
    async createSession(input) {
      const res = await app.request('/verification-sessions', {
        method: 'POST',
        headers: { authorization: `Bearer ${demoSite.apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify(input),
      });
      return { status: res.status, body: await res.json() };
    },
    async redeem(input) {
      const res = await app.request('/redeem', {
        method: 'POST',
        headers: { authorization: `Bearer ${demoSite.apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify(input),
      });
      return { status: res.status, body: await res.json() };
    },
  };
  app.route('/demo', demoSiteRoutes({ db, site: demoSite, client, origin: config.origin }));

  // Static pages (first-party, top-level; same origin as the API and RP ID).
  const pages: Record<string, string> = { '/': 'index.html', '/verify': 'verify.html', '/diagnostics': 'diagnostics.html', '/demo': 'demo/index.html', '/demo/': 'demo/index.html' };
  const sendFile = async (c: Context<AppEnv>, rel: string) => {
    const abs = resolve(PUBLIC_DIR, normalize(rel).replace(/^([/\\])+/, ''));
    if (!abs.startsWith(resolve(PUBLIC_DIR) + sep)) return c.text('not found', 404);
    try {
      const body = await readFile(abs);
      c.header('Content-Type', MIME[extname(abs)] ?? 'application/octet-stream');
      return c.body(body);
    } catch {
      return c.text('not found', 404);
    }
  };
  for (const [route, file] of Object.entries(pages)) app.get(route, (c) => sendFile(c, file));
  app.get('/static/*', (c) => sendFile(c, c.req.path.replace(/^\/static\//, 'static/')));
  app.get('/vendor/*', (c) => sendFile(c, c.req.path.replace(/^\/vendor\//, 'vendor/')));

  app.onError((err, c) => {
    log.error('unhandled error', { path: c.req.path, error: err.message });
    return c.json({ error: 'internal_error' }, 500);
  });

  return { app, deps };
}

