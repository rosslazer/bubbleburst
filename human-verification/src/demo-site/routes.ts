/**
 * Demo relying site backend. Logically a separate system that owns:
 *   - the form and its canonical submission digest,
 *   - a site API key for the verification service,
 *   - the decision to accept a submission only after a successful server-side redeem.
 *
 * Frontend callbacks (the approval token arriving in the browser) are never treated as authorization;
 * only the redeem response from the verification service is.
 */
import { Hono } from 'hono';
import { z } from 'zod';
import type { DB } from '../db.js';
import { sha256Hex } from '../ids.js';
import type { SiteConfig } from '../config.js';

export interface VerificationApiClient {
  createSession(input: { action: string; submissionDigest: string; returnUrl: string }): Promise<{ status: number; body: any }>;
  redeem(input: { approvalToken: string; sessionId: string; action: string; submissionDigest: string }): Promise<{ status: number; body: any }>;
}

const SubmitSchema = z.object({
  name: z.string().min(1).max(200),
  email: z.string().min(3).max(200),
  message: z.string().min(1).max(5000),
});

export const DEMO_ACTION = 'contact-form:submit';

/** Canonical digest: sorted keys, JSON, sha256 hex. Any field change produces a new digest. */
export function submissionDigest(action: string, fields: Record<string, string>): string {
  const canonical = JSON.stringify({ action, fields: Object.fromEntries(Object.entries(fields).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) });
  return sha256Hex(canonical);
}

export function demoSiteRoutes(opts: { db: DB; site: SiteConfig; client: VerificationApiClient; origin: string }) {
  const { db, client, origin } = opts;
  const app = new Hono();

  app.post('/api/submit', async (c) => {
    const parsed = SubmitSchema.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: 'invalid_form', issues: parsed.error.issues }, 400);
    const digest = submissionDigest(DEMO_ACTION, parsed.data);
    const res = await client.createSession({ action: DEMO_ACTION, submissionDigest: digest, returnUrl: `${origin}/demo/complete` });
    if (res.status !== 201) return c.json({ error: 'verification_unavailable', upstream: res.body }, 502);
    const sessionId: string = res.body.session.id;
    db.prepare('INSERT INTO demo_submissions (session_id, action, submission_digest, payload, state, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      sessionId,
      DEMO_ACTION,
      digest,
      JSON.stringify(parsed.data),
      'awaiting-verification',
      Date.now(),
    );
    return c.json({ sessionId, verifyUrl: res.body.verifyUrl, submissionDigest: digest });
  });

  // The verification page posts the approval token here. The site backend redeems it server-side
  // against the exact session/action/digest it recorded; nothing from the browser is trusted.
  app.post('/complete', async (c) => {
    const form = await c.req.parseBody();
    const sessionId = typeof form.sessionId === 'string' ? form.sessionId : '';
    const approvalToken = typeof form.approvalToken === 'string' ? form.approvalToken : '';
    const pending = db.prepare('SELECT * FROM demo_submissions WHERE session_id = ?').get(sessionId) as
      | { session_id: string; action: string; submission_digest: string; payload: string; state: string }
      | undefined;
    if (!pending) return c.html(resultPage('Unknown submission', 'No pending submission matches this session.', false), 404);
    const res = await client.redeem({ approvalToken, sessionId, action: pending.action, submissionDigest: pending.submission_digest });
    const ok = res.status === 200 && res.body?.ok === true;
    db.prepare('UPDATE demo_submissions SET state = ?, accepted_at = ?, redeem_result = ? WHERE session_id = ?').run(ok ? 'accepted' : 'rejected', ok ? Date.now() : null, JSON.stringify(res.body), sessionId);
    if (!ok) return c.html(resultPage('Submission not accepted', `The verification service refused the approval token (${res.body?.reason ?? res.status}).`, false), 409);
    const payload = JSON.parse(pending.payload) as { name: string };
    return c.html(
      resultPage(
        'Submission accepted',
        `Thanks ${escapeHtml(payload.name)}. The verification service confirmed an approval bound to this exact submission (credential meets the configured authenticator policy; this is not proof of a unique human).`,
        true,
        res.body,
      ),
    );
  });

  app.get('/api/submissions/:sessionId', (c) => {
    const row = db.prepare('SELECT session_id, action, submission_digest, state, created_at, accepted_at, redeem_result FROM demo_submissions WHERE session_id = ?').get(c.req.param('sessionId'));
    if (!row) return c.json({ error: 'not_found' }, 404);
    return c.json(row);
  });

  return app;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
}

function resultPage(title: string, message: string, ok: boolean, detail?: unknown): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="/static/app.css"></head><body><main class="card">
<h1 data-testid="result-title" class="${ok ? 'ok' : 'bad'}">${escapeHtml(title)}</h1>
<p data-testid="result-message">${message}</p>
${detail ? `<details><summary>Redeem response</summary><pre>${escapeHtml(JSON.stringify(detail, null, 2))}</pre></details>` : ''}
<p><a href="/demo/">Back to the demo form</a></p></main></body></html>`;
}
