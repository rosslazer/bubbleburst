/**
 * Verification service API (Phase 2 integration contract).
 *
 *   POST /verification-sessions                         site auth   create session
 *   GET  /verification-sessions/:id                     site auth OR client token   status
 *   POST /verification-sessions/:id/registration/options       client token
 *   POST /verification-sessions/:id/registration/verify        client token
 *   POST /verification-sessions/:id/authentication/options     client token
 *   POST /verification-sessions/:id/authentication/verify      client token  → approval token
 *   POST /redeem                                        site auth   one-time redemption
 *
 * Client-token endpoints are called from the first-party verification page. They require the
 * `X-Client-Token` header (a custom header forces a CORS preflight, which defeats cross-site form
 * posts) and an `Origin` header matching the configured origin when present.
 */
import { Hono } from 'hono';
import { z } from 'zod';
import type { AppDeps, AppEnv } from '../app.js';
import type { SessionRow } from '../db.js';
import { WebAuthnService } from '../services/webauthnService.js';

const CreateSessionSchema = z.object({
  action: z.string().min(1).max(200),
  submissionDigest: z.string().regex(/^[0-9a-f]{64}$/, 'sha256 hex digest'),
  returnUrl: z.string().url().max(2000).optional(),
});

const RedeemSchema = z.object({
  approvalToken: z.string().min(20).max(200),
  sessionId: z.string().min(1).max(200),
  action: z.string().min(1).max(200),
  submissionDigest: z.string().regex(/^[0-9a-f]{64}$/),
});

const OptionsSchema = z.object({ hints: z.array(z.string()).optional() }).optional();

export function sessionView(s: SessionRow, viewer: 'site' | 'client') {
  const base = {
    id: s.id,
    state: s.state,
    action: s.action,
    submissionDigest: s.submission_digest,
    createdAt: new Date(s.created_at).toISOString(),
    expiresAt: new Date(s.expires_at).toISOString(),
    returnUrl: s.return_url,
    rejectedReason: s.rejected_reason,
  };
  if (viewer === 'site') {
    return { ...base, siteId: s.site_id, approvedAt: s.approved_at ? new Date(s.approved_at).toISOString() : null, consumedAt: s.consumed_at ? new Date(s.consumed_at).toISOString() : null, approvingCredentialId: s.approving_credential_id };
  }
  return base;
}

export function verificationRoutes(deps: AppDeps) {
  const { config, sessions, webauthn, rateLimiter, log, clientIp, requireSite, requireClient } = deps;
  const app = new Hono<AppEnv>();

  app.post('/verification-sessions', requireSite, async (c) => {
    const site = c.get('site');
    const ip = clientIp(c);
    const rl1 = rateLimiter.consume(`site:${site.id}:sessions`, config.rateLimits.sessionsPerSite);
    const rl2 = rateLimiter.consume(`ip:${ip}:sessions`, config.rateLimits.sessionsPerIp);
    if (!rl1.allowed || !rl2.allowed) {
      return c.json({ error: 'rate_limited', retryAfterSec: Math.max(rl1.retryAfterSec, rl2.retryAfterSec) }, 429);
    }
    const parsed = CreateSessionSchema.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: 'invalid_request', issues: parsed.error.issues }, 400);
    const { session, clientToken } = sessions.create({
      siteId: site.id,
      action: parsed.data.action,
      submissionDigest: parsed.data.submissionDigest,
      clientIp: ip,
      returnUrl: parsed.data.returnUrl ?? null,
      ttlSec: config.sessionTtlSec,
    });
    const verifyUrl = `${config.origin}/verify#s=${encodeURIComponent(session.id)}&t=${encodeURIComponent(clientToken)}`;
    log.info('session created', { sessionId: session.id, siteId: site.id, action: session.action });
    return c.json({ session: sessionView(session, 'site'), clientToken, verifyUrl }, 201);
  });

  app.get('/verification-sessions/:id', async (c) => {
    const session = sessions.get(c.req.param('id'));
    if (!session) return c.json({ error: 'not_found' }, 404);
    // Site backend with a matching site key sees the full view; the initiating browser context sees
    // the limited view; anyone else sees nothing (no existence oracle beyond 404).
    const auth = c.req.header('authorization');
    if (auth) {
      const site = deps.siteFromAuth(auth);
      if (!site || site.id !== session.site_id) return c.json({ error: 'forbidden' }, 403);
      return c.json({ session: sessionView(session, 'site') });
    }
    if (!sessions.clientAuthorized(session, c.req.header('x-client-token'))) return c.json({ error: 'forbidden' }, 403);
    return c.json({ session: sessionView(session, 'client'), policy: { version: config.policy.version } });
  });

  const clientCeremony = new Hono<AppEnv>();
  clientCeremony.use('*', requireClient);

  clientCeremony.post('/registration/options', async (c) => {
    const session = c.get('session');
    if (session.state !== 'pending') return c.json({ error: 'session_not_pending', state: session.state }, 409);
    const ip = clientIp(c);
    const rl = rateLimiter.consume(`session:${session.id}:attempts`, config.rateLimits.attemptsPerSession);
    const rl2 = rateLimiter.consume(`ip:${ip}:enroll`, config.rateLimits.enrollmentsPerIp);
    if (!rl.allowed || !rl2.allowed) return c.json({ error: 'rate_limited', retryAfterSec: Math.max(rl.retryAfterSec, rl2.retryAfterSec) }, 429);
    const body = OptionsSchema.safeParse(await c.req.json().catch(() => ({})));
    const hints = WebAuthnService.sanitizeHints(body.success ? body.data?.hints : undefined);
    const options = await webauthn.registrationOptions({ lane: 'strict', sessionId: session.id, hints });
    return c.json({ options, lane: 'strict', note: 'Enrollment never approves the session. A fresh assertion is required afterwards.' });
  });

  clientCeremony.post('/registration/verify', async (c) => {
    const session = c.get('session');
    if (session.state !== 'pending') return c.json({ error: 'session_not_pending', state: session.state }, 409);
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body !== 'object' || !body.response) return c.json({ error: 'invalid_request' }, 400);
    const verdict = await webauthn.verifyRegistration({ lane: 'strict', sessionId: session.id, response: body.response });
    const httpStatus = verdict.challengeError ? 400 : 200;
    return c.json(
      {
        lane: 'strict',
        enrolled: verdict.stored,
        credentialId: verdict.credentialId,
        libraryVerified: verdict.libraryVerified,
        libraryError: verdict.libraryError,
        challengeError: verdict.challengeError,
        policy: verdict.policy,
        meetsPolicy: verdict.stored && verdict.policy?.trusted === true,
        sessionState: sessions.get(session.id)?.state,
        note: verdict.stored && verdict.policy?.trusted ? 'Credential meets the configured authenticator policy. Approve the submission with a fresh assertion.' : 'Credential does not meet the configured authenticator policy. It cannot approve submissions.',
      },
      httpStatus,
    );
  });

  clientCeremony.post('/authentication/options', async (c) => {
    const session = c.get('session');
    if (session.state !== 'pending') return c.json({ error: 'session_not_pending', state: session.state }, 409);
    const rl = rateLimiter.consume(`session:${session.id}:attempts`, config.rateLimits.attemptsPerSession);
    if (!rl.allowed) return c.json({ error: 'rate_limited', retryAfterSec: rl.retryAfterSec }, 429);
    const body = OptionsSchema.safeParse(await c.req.json().catch(() => ({})));
    const hints = WebAuthnService.sanitizeHints(body.success ? body.data?.hints : undefined);
    const options = await webauthn.authenticationOptions({ lane: 'strict', sessionId: session.id, hints });
    return c.json({ options, lane: 'strict' });
  });

  clientCeremony.post('/authentication/verify', async (c) => {
    const session = c.get('session');
    if (session.state !== 'pending') return c.json({ error: 'session_not_pending', state: session.state }, 409);
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body !== 'object' || !body.response) return c.json({ error: 'invalid_request' }, 400);
    const verdict = await webauthn.verifyAuthentication({ lane: 'strict', sessionId: session.id, response: body.response });
    let approval: { token: string; expiresAt: number } | null = null;
    if (verdict.eligibleForApproval && verdict.credentialId) {
      // Re-check everything time-sensitive right before minting: expiry, rate limits, state.
      const fresh = sessions.get(session.id);
      const rlc = rateLimiter.consume(`cred:${verdict.credentialId}:approvals`, config.rateLimits.approvalsPerCredential);
      if (!fresh || fresh.state !== 'pending') {
        verdict.reasons.push(`session no longer pending (${fresh?.state ?? 'missing'})`);
      } else if (!rlc.allowed) {
        verdict.reasons.push('credential approval rate limit exceeded');
      } else {
        approval = sessions.approve(session.id, verdict.credentialId, config.tokenTtlSec);
      }
    }
    const finalState = sessions.get(session.id)?.state;
    log.info('authentication', { sessionId: session.id, verified: verdict.verified, approved: !!approval, credentialId: verdict.credentialId, reasons: verdict.reasons });
    return c.json({
      lane: 'strict',
      verified: verdict.verified,
      approved: !!approval,
      approvalToken: approval?.token ?? null,
      approvalTokenExpiresAt: approval ? new Date(approval.expiresAt).toISOString() : null,
      returnUrl: session.return_url,
      sessionState: finalState,
      evidence: {
        credentialId: verdict.credentialId,
        userVerified: verdict.userVerified,
        counter: verdict.counter,
        backup: verdict.backup,
        credentialPolicyTrusted: verdict.credentialPolicyTrusted,
        credentialPolicyVersion: verdict.credentialPolicyVersion,
        policyVersionCurrent: verdict.policyVersionCurrent,
        credentialPolicy: verdict.credentialPolicy,
      },
      reasons: verdict.reasons,
      error: verdict.error,
      note: approval
        ? 'Assertion verified against a credential that meets the configured authenticator policy. This is not proof of a unique human or of Bluetooth proximity.'
        : 'No approval issued.',
    });
  });

  app.route('/verification-sessions/:id', clientCeremony);

  app.post('/redeem', requireSite, async (c) => {
    const site = c.get('site');
    const rl = rateLimiter.consume(`site:${site.id}:redeems`, config.rateLimits.redeemsPerSite);
    if (!rl.allowed) return c.json({ error: 'rate_limited', retryAfterSec: rl.retryAfterSec }, 429);
    const parsed = RedeemSchema.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: 'invalid_request', issues: parsed.error.issues }, 400);
    const outcome = sessions.redeem({
      siteId: site.id,
      sessionId: parsed.data.sessionId,
      action: parsed.data.action,
      submissionDigest: parsed.data.submissionDigest,
      token: parsed.data.approvalToken,
    });
    if (!outcome.ok) {
      log.warn('redeem rejected', { siteId: site.id, sessionId: parsed.data.sessionId, reason: outcome.reason });
      return c.json({ ok: false, reason: outcome.reason }, 409);
    }
    log.info('redeemed', { siteId: site.id, sessionId: outcome.session.id, credentialId: outcome.token.credential_id });
    return c.json({
      ok: true,
      session: sessionView(outcome.session, 'site'),
      approvedAt: new Date(outcome.session.approved_at!).toISOString(),
      consumedAt: new Date(outcome.token.consumed_at!).toISOString(),
      credentialId: outcome.token.credential_id,
      assurance: 'credential-meets-configured-authenticator-policy',
    });
  });

  return app;
}
