/**
 * Diagnostic lane: exercises the same ceremonies and the same policy evaluator, but is never bound
 * to a verification session and never issues an approval token. Results are stored as sanitized
 * evidence rows for the device matrix.
 */
import { Hono } from 'hono';
import { z } from 'zod';
import type { AppDeps, AppEnv } from '../app.js';
import { WebAuthnService } from '../services/webauthnService.js';
import { randomId } from '../ids.js';
import type { DiagnosticRunRow } from '../db.js';

const ManualObservationSchema = z.object({
  device: z.string().max(200),
  os: z.string().max(200),
  browser: z.string().max(200),
  provider: z.string().max(200),
  scenario: z.string().max(200),
  observedUx: z.string().max(4000),
  durationSec: z.number().nonnegative().max(3600).optional(),
  bluetooth: z.enum(['on', 'off', 'unknown']).optional(),
  phoneRemote: z.boolean().optional(),
  tester: z.string().max(200).optional(),
  notes: z.string().max(4000).optional(),
});

const SaveRunSchema = z.object({
  kind: z.enum(['registration', 'authentication']),
  serverVerified: z.record(z.string(), z.unknown()),
  clientReported: z.record(z.string(), z.unknown()),
  manuallyObserved: ManualObservationSchema,
});

export function diagnosticsRoutes(deps: AppDeps) {
  const { config, db, webauthn, rateLimiter, clientIp } = deps;
  const app = new Hono<AppEnv>();

  app.use('*', async (c, next) => {
    if (!config.diagnosticsEnabled) return c.json({ error: 'diagnostics_disabled' }, 404);
    const rl = rateLimiter.consume(`ip:${clientIp(c)}:diag`, config.rateLimits.diagnosticsPerIp);
    if (!rl.allowed) return c.json({ error: 'rate_limited', retryAfterSec: rl.retryAfterSec }, 429);
    await next();
  });

  app.post('/registration/options', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { hints?: unknown };
    const options = await webauthn.registrationOptions({ lane: 'diagnostic', sessionId: null, hints: WebAuthnService.sanitizeHints(body.hints) });
    return c.json({ options, lane: 'diagnostic' });
  });

  app.post('/registration/verify', async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body !== 'object' || !body.response) return c.json({ error: 'invalid_request' }, 400);
    const verdict = await webauthn.verifyRegistration({ lane: 'diagnostic', sessionId: null, response: body.response });
    return c.json({
      lane: 'diagnostic',
      approvalToken: null,
      libraryVerified: verdict.libraryVerified,
      libraryError: verdict.libraryError,
      challengeError: verdict.challengeError,
      credentialId: verdict.credentialId,
      stored: verdict.stored,
      policy: verdict.policy,
      note: 'Diagnostic lane: no approval token is ever issued here, regardless of outcome.',
    });
  });

  app.post('/authentication/options', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { hints?: unknown };
    const options = await webauthn.authenticationOptions({ lane: 'diagnostic', sessionId: null, hints: WebAuthnService.sanitizeHints(body.hints) });
    return c.json({ options, lane: 'diagnostic' });
  });

  app.post('/authentication/verify', async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body !== 'object' || !body.response) return c.json({ error: 'invalid_request' }, 400);
    const verdict = await webauthn.verifyAuthentication({ lane: 'diagnostic', sessionId: null, response: body.response });
    return c.json({
      lane: 'diagnostic',
      approvalToken: null,
      approved: false,
      verified: verdict.verified,
      error: verdict.error,
      evidence: {
        credentialId: verdict.credentialId,
        userVerified: verdict.userVerified,
        counter: verdict.counter,
        backup: verdict.backup,
        credentialPolicy: verdict.credentialPolicy,
        wouldMeetStrictPolicy: verdict.credentialPolicy?.trusted === true,
      },
      reasons: verdict.reasons,
      note: 'Diagnostic lane: no approval token is ever issued here, regardless of outcome.',
    });
  });

  app.post('/runs', async (c) => {
    const parsed = SaveRunSchema.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: 'invalid_request', issues: parsed.error.issues }, 400);
    const row: DiagnosticRunRow = { id: randomId('dr_'), created_at: Date.now(), kind: parsed.data.kind, evidence: JSON.stringify(parsed.data) };
    db.prepare('INSERT INTO diagnostic_runs (id, created_at, kind, evidence) VALUES (?, ?, ?, ?)').run(row.id, row.created_at, row.kind, row.evidence);
    return c.json({ id: row.id, createdAt: new Date(row.created_at).toISOString() }, 201);
  });

  app.get('/runs', (c) => {
    const rows = db.prepare('SELECT * FROM diagnostic_runs ORDER BY created_at DESC LIMIT 500').all() as DiagnosticRunRow[];
    return c.json({ runs: rows.map((r) => ({ id: r.id, createdAt: new Date(r.created_at).toISOString(), kind: r.kind, ...(JSON.parse(r.evidence) as object) })) });
  });

  return app;
}
