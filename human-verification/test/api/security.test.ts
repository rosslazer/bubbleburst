/**
 * Security-boundary tests: challenge binding, replay, origin/RP ID, signature, UV, tokens,
 * concurrency, CSRF-style access, rate limits, diagnostics isolation.
 */
import { describe, expect, it } from 'vitest';
import { createHarness, createSession, enroll, assertWith, redeem, SITE_A, DIGEST_B, TEST_ORIGIN } from '../helpers/testApp.js';
import { isoBase64URL } from '@simplewebauthn/server/helpers';

async function trustedSession(h: Awaited<ReturnType<typeof createHarness>>) {
  const s = await createSession(h);
  const e = await enroll(h, s, { kind: 'full', ca: h.ca });
  expect(e.verify!.body.meetsPolicy).toBe(true);
  return { s, cred: e.cred };
}

describe('challenge and ceremony binding', () => {
  it('rejects wrong origin, wrong RP ID, wrong challenge and missing UV on assertions', async () => {
    const h = await createHarness();
    const { s, cred } = await trustedSession(h);
    for (const [label, overrides] of [
      ['origin', { origin: 'https://evil.example' }],
      ['rpId', { rpId: 'evil.example' }],
      ['challenge', { challengeOverride: isoBase64URL.fromBuffer(new Uint8Array(32).fill(1)) }],
      ['uv', { uv: false }],
      ['signature', { corruptSignature: true }],
    ] as const) {
      const a = await assertWith(h, s, cred, overrides);
      expect(a.verify!.body.approved, label).toBe(false);
      expect(a.verify!.body.verified, label).toBe(false);
      expect(a.verify!.body.approvalToken, label).toBeNull();
    }
    expect((await h.http.json(`/verification-sessions/${s.id}`, { site: SITE_A })).body.session.state).toBe('pending');
  });

  it('rejects wrong origin/RP ID/UV at registration and stores nothing', async () => {
    const h = await createHarness();
    const s = await createSession(h);
    for (const [label, overrides] of [
      ['origin', { origin: 'https://evil.example' }],
      ['rpId', { rpId: 'evil.example' }],
      ['uv', { uv: false }],
    ] as const) {
      const e = await enroll(h, s, { kind: 'full', ca: h.ca }, {}, overrides);
      expect(e.verify!.body.enrolled, label).toBe(false);
      expect(e.verify!.body.meetsPolicy, label).toBe(false);
      expect(e.verify!.body.libraryVerified, label).toBe(false);
    }
  });

  it('rejects an expired challenge', async () => {
    const h = await createHarness({ config: { challengeTtlSec: 1 } });
    const { s, cred } = await trustedSession(h);
    const opt = await h.http.json(`/verification-sessions/${s.id}/authentication/options`, { clientToken: s.clientToken, body: {} });
    h.deps.db.prepare('UPDATE challenges SET expires_at = ? WHERE challenge = ?').run(Date.now() - 1, opt.body.options.challenge);
    const v = await h.http.json(`/verification-sessions/${s.id}/authentication/verify`, { clientToken: s.clientToken, body: { response: await cred.assert(opt.body.options) } });
    expect(v.body.error).toBe('challenge expired');
    expect(v.body.approved).toBe(false);
  });

  it('rejects replayed assertions and reused enrollment challenges', async () => {
    const h = await createHarness();
    const { s, cred } = await trustedSession(h);
    const a = await assertWith(h, s, cred);
    expect(a.verify!.body.approved).toBe(true);
    // Replay the identical assertion against a new pending session and against the same session.
    const s2 = await createSession(h);
    const replay = await h.http.json(`/verification-sessions/${s2.id}/authentication/verify`, { clientToken: s2.clientToken, body: { response: a.response } });
    expect(replay.body.approved).toBe(false);
    expect(replay.body.error).toContain('different session');
    const replaySame = await h.http.json(`/verification-sessions/${s.id}/authentication/verify`, { clientToken: s.clientToken, body: { response: a.response } });
    expect(replaySame.status).toBe(409); // session no longer pending
    // Reused registration challenge.
    const s3 = await createSession(h);
    const opt = await h.http.json(`/verification-sessions/${s3.id}/registration/options`, { clientToken: s3.clientToken, body: {} });
    const c1 = await (await import('../helpers/fixtureAuthenticator.js')).FixtureCredential.create({ rpId: 'localhost', origin: TEST_ORIGIN });
    const r1 = await h.http.json(`/verification-sessions/${s3.id}/registration/verify`, { clientToken: s3.clientToken, body: { response: await c1.register(opt.body.options, { kind: 'full', ca: h.ca }) } });
    expect(r1.body.enrolled).toBe(true);
    const c2 = await (await import('../helpers/fixtureAuthenticator.js')).FixtureCredential.create({ rpId: 'localhost', origin: TEST_ORIGIN });
    const r2 = await h.http.json(`/verification-sessions/${s3.id}/registration/verify`, { clientToken: s3.clientToken, body: { response: await c2.register(opt.body.options, { kind: 'full', ca: h.ca }) } });
    expect(r2.status).toBe(400);
    expect(r2.body.challengeError).toBe('challenge already used');
    expect(r2.body.enrolled).toBe(false);
  });

  it('a challenge issued for one session cannot be answered in another (session swapping)', async () => {
    const h = await createHarness();
    const { s, cred } = await trustedSession(h);
    const other = await createSession(h, { digest: DIGEST_B });
    const opt = await h.http.json(`/verification-sessions/${other.id}/authentication/options`, { clientToken: other.clientToken, body: {} });
    const v = await h.http.json(`/verification-sessions/${s.id}/authentication/verify`, { clientToken: s.clientToken, body: { response: await cred.assert(opt.body.options) } });
    expect(v.body.error).toBe('challenge bound to a different session');
    expect(v.body.approved).toBe(false);
  });

  it('enforces signature counter semantics only when a counter is in use', async () => {
    const h = await createHarness();
    const s = await createSession(h);
    const e = await enroll(h, s, { kind: 'full', ca: h.ca }, { counter: 5 });
    expect(e.verify!.body.meetsPolicy).toBe(true);
    const bad = await assertWith(h, s, e.cred, { counterOverride: 5 }); // no increase
    expect(bad.verify!.body.approved).toBe(false);
    expect(bad.verify!.body.error).toContain('counter');
    const ok = await assertWith(h, s, e.cred, { counterOverride: 6 });
    expect(ok.verify!.body.approved).toBe(true);
    // Zero counters (synced passkeys) are not treated as clone evidence.
    const s2 = await createSession(h);
    const z = await enroll(h, s2, { kind: 'full', ca: h.ca }, { counter: 0 });
    const zz = await assertWith(h, s2, z.cred, { counterOverride: 0 });
    expect(zz.verify!.body.evidence.counter.checked).toBe(false);
    expect(zz.verify!.body.approved).toBe(true);
  });
});

describe('approval tokens', () => {
  it('cross-session/site/action/payload substitution fails; a changed form requires a new approval', async () => {
    const h = await createHarness();
    const { s, cred } = await trustedSession(h);
    const a = await assertWith(h, s, cred);
    const token = a.verify!.body.approvalToken;
    expect((await redeem(h, s, token, { digest: DIGEST_B })).body.reason).toBe('BINDING_MISMATCH');
    expect((await redeem(h, s, token, { action: 'other-form:submit' })).body.reason).toBe('BINDING_MISMATCH');
    expect((await redeem(h, s, token, { sessionId: (await createSession(h)).id })).body.reason).toBe('BINDING_MISMATCH');
    const ok = await redeem(h, s, token);
    expect(ok.body.ok).toBe(true);
  });

  it('expired tokens fail', async () => {
    const h = await createHarness({ config: { tokenTtlSec: 1 } });
    const { s, cred } = await trustedSession(h);
    const a = await assertWith(h, s, cred);
    h.deps.db.prepare('UPDATE approval_tokens SET expires_at = ? WHERE session_id = ?').run(Date.now() - 1, s.id);
    expect((await redeem(h, s, a.verify!.body.approvalToken)).body.reason).toBe('TOKEN_EXPIRED');
  });

  it('concurrent redemption accepts exactly once', async () => {
    const h = await createHarness();
    const { s, cred } = await trustedSession(h);
    const a = await assertWith(h, s, cred);
    const results = await Promise.all(Array.from({ length: 25 }, () => redeem(h, s, a.verify!.body.approvalToken)));
    expect(results.filter((r) => r.status === 200 && r.body.ok).length).toBe(1);
    expect(results.filter((r) => r.status === 409).length).toBe(24);
  });

  it('tokens are unguessable opaque strings and only hashes are stored', async () => {
    const h = await createHarness();
    const { s, cred } = await trustedSession(h);
    const a = await assertWith(h, s, cred);
    const token: string = a.verify!.body.approvalToken;
    expect(token.length).toBeGreaterThan(40);
    const rows = h.deps.db.prepare('SELECT token_hash FROM approval_tokens').all() as { token_hash: string }[];
    expect(rows.some((r) => r.token_hash === token || token.includes(r.token_hash))).toBe(false);
  });
});

describe('access control and CSRF posture', () => {
  it('client endpoints require the client token, JSON content type and a matching Origin when present', async () => {
    const h = await createHarness();
    const s = await createSession(h);
    expect((await h.http.json(`/verification-sessions/${s.id}/registration/options`, { body: {} })).status).toBe(403);
    expect((await h.http.json(`/verification-sessions/${s.id}/registration/options`, { body: {}, clientToken: 'hvc_wrong' })).status).toBe(403);
    expect((await h.http.json(`/verification-sessions/${s.id}/registration/options`, { body: {}, clientToken: s.clientToken, headers: { origin: 'https://evil.example' } })).status).toBe(403);
    expect((await h.http.json(`/verification-sessions/${s.id}/registration/options`, { rawBody: 'a=b', clientToken: s.clientToken, headers: { 'content-type': 'application/x-www-form-urlencoded' } })).status).toBe(415);
    expect((await h.http.json(`/verification-sessions/${s.id}/registration/options`, { body: {}, clientToken: s.clientToken, headers: { origin: TEST_ORIGIN } })).status).toBe(200);
    expect((await h.http.json(`/verification-sessions/${s.id}`)).status).toBe(403);
    expect((await h.http.json('/verification-sessions/does-not-exist', { clientToken: 'x' })).status).toBe(404);
  });

  it('site endpoints require a valid site key', async () => {
    const h = await createHarness();
    expect((await h.http.json('/verification-sessions', { body: { action: 'a', submissionDigest: 'a'.repeat(64) } })).status).toBe(401);
    expect((await h.http.json('/verification-sessions', { site: { apiKey: 'nope' }, body: { action: 'a', submissionDigest: 'a'.repeat(64) } })).status).toBe(401);
    expect((await h.http.json('/redeem', { body: { approvalToken: 'hvt_xxxxxxxxxxxxxxxxxxxxxxxx', sessionId: 'x', action: 'a', submissionDigest: 'a'.repeat(64) } })).status).toBe(401);
  });

  it('rate limits sessions per IP and attempts per session', async () => {
    const h = await createHarness({ config: { rateLimits: { sessionsPerSite: { max: 100, windowSec: 60 }, sessionsPerIp: { max: 2, windowSec: 60 }, enrollmentsPerIp: { max: 100, windowSec: 60 }, attemptsPerSession: { max: 1, windowSec: 60 }, approvalsPerCredential: { max: 100, windowSec: 60 }, redeemsPerSite: { max: 100, windowSec: 60 }, diagnosticsPerIp: { max: 100, windowSec: 60 } } } });
    const s = await createSession(h);
    await createSession(h);
    const third = await h.http.json('/verification-sessions', { site: SITE_A, body: { action: 'a', submissionDigest: 'a'.repeat(64) } });
    expect(third.status).toBe(429);
    expect((await h.http.json(`/verification-sessions/${s.id}/authentication/options`, { clientToken: s.clientToken, body: {} })).status).toBe(200);
    expect((await h.http.json(`/verification-sessions/${s.id}/authentication/options`, { clientToken: s.clientToken, body: {} })).status).toBe(429);
  });

  it('no approval possible once a session is expired', async () => {
    const h = await createHarness();
    const { s, cred } = await trustedSession(h);
    h.deps.db.prepare('UPDATE verification_sessions SET expires_at = ? WHERE id = ?').run(Date.now() - 1, s.id);
    const a = await assertWith(h, s, cred);
    expect(a.options.status).toBe(409);
  });
});

describe('vendor-root pinning', () => {
  it('startup fails if the embedded Apple root does not match the published fingerprint', async () => {
    const { PINNED_ROOT_FINGERPRINTS } = await import('../../src/policy/trustStore.js');
    const original = PINNED_ROOT_FINGERPRINTS['vendor:apple']![0]!.fingerprint;
    PINNED_ROOT_FINGERPRINTS['vendor:apple']![0]!.fingerprint = 'deadbeef';
    try {
      await expect(createHarness()).rejects.toThrow(/pin failure/);
    } finally {
      PINNED_ROOT_FINGERPRINTS['vendor:apple']![0]!.fingerprint = original;
    }
  });
});
