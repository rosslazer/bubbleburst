import { describe, expect, it } from 'vitest';
import { openDatabase } from '../../src/db.js';
import { SessionService } from '../../src/services/sessions.js';
import { RateLimiter } from '../../src/ratelimit.js';

const base = { siteId: 's1', action: 'a', submissionDigest: 'd'.repeat(64), clientIp: null, returnUrl: null, ttlSec: 60 };

describe('SessionService state machine and tokens', () => {
  it('pending → approved → consumed, exactly once', () => {
    const svc = new SessionService(openDatabase(':memory:'));
    const { session } = svc.create(base);
    expect(session.state).toBe('pending');
    const approval = svc.approve(session.id, 'cred', 60)!;
    expect(approval.token.startsWith('hvt_')).toBe(true);
    expect(svc.get(session.id)!.state).toBe('approved');
    expect(svc.approve(session.id, 'cred', 60)).toBeNull(); // no second token
    const r1 = svc.redeem({ siteId: 's1', sessionId: session.id, action: 'a', submissionDigest: base.submissionDigest, token: approval.token });
    expect(r1.ok).toBe(true);
    expect(svc.get(session.id)!.state).toBe('consumed');
    const r2 = svc.redeem({ siteId: 's1', sessionId: session.id, action: 'a', submissionDigest: base.submissionDigest, token: approval.token });
    expect(r2).toEqual({ ok: false, reason: 'TOKEN_ALREADY_CONSUMED' });
  });

  it('rejects tokens for a different site, session, action or digest without consuming them', () => {
    const svc = new SessionService(openDatabase(':memory:'));
    const { session } = svc.create(base);
    const { token } = svc.approve(session.id, 'cred', 60)!;
    const good = { siteId: 's1', sessionId: session.id, action: 'a', submissionDigest: base.submissionDigest, token };
    expect(svc.redeem({ ...good, siteId: 's2' })).toEqual({ ok: false, reason: 'BINDING_MISMATCH' });
    expect(svc.redeem({ ...good, sessionId: 'other' })).toEqual({ ok: false, reason: 'BINDING_MISMATCH' });
    expect(svc.redeem({ ...good, action: 'b' })).toEqual({ ok: false, reason: 'BINDING_MISMATCH' });
    expect(svc.redeem({ ...good, submissionDigest: 'e'.repeat(64) })).toEqual({ ok: false, reason: 'BINDING_MISMATCH' });
    expect(svc.redeem({ ...good, token: 'hvt_unknown' })).toEqual({ ok: false, reason: 'TOKEN_UNKNOWN' });
    expect(svc.redeem(good).ok).toBe(true);
  });

  it('expires tokens and sessions', () => {
    const svc = new SessionService(openDatabase(':memory:'));
    const t0 = 1_000_000;
    const { session } = svc.create(base, t0);
    const { token } = svc.approve(session.id, 'cred', 10, t0)!;
    expect(svc.redeem({ siteId: 's1', sessionId: session.id, action: 'a', submissionDigest: base.submissionDigest, token }, t0 + 11_000)).toEqual({ ok: false, reason: 'TOKEN_EXPIRED' });
    const { session: s2 } = svc.create(base, t0);
    expect(svc.get(s2.id, t0 + 61_000)!.state).toBe('expired');
    expect(svc.approve(s2.id, 'cred', 10, t0 + 61_000)).toBeNull();
  });

  it('rejected sessions are terminal', () => {
    const svc = new SessionService(openDatabase(':memory:'));
    const { session } = svc.create(base);
    svc.reject(session.id, 'test');
    expect(svc.get(session.id)!.state).toBe('rejected');
    expect(svc.approve(session.id, 'cred', 10)).toBeNull();
  });

  it('challenges are single-use, bound to session/lane/kind, and expire', () => {
    const svc = new SessionService(openDatabase(':memory:'));
    const t0 = 1_000_000;
    const { session } = svc.create(base, t0);
    svc.createChallenge({ sessionId: session.id, lane: 'strict', kind: 'registration', ttlSec: 10, challenge: 'C1' }, t0);
    expect(svc.consumeChallenge({ challenge: 'C1', sessionId: 'other', lane: 'strict', kind: 'registration' }, t0).ok).toBe(false);
    expect(svc.consumeChallenge({ challenge: 'C1', sessionId: session.id, lane: 'diagnostic', kind: 'registration' }, t0).ok).toBe(false);
    expect(svc.consumeChallenge({ challenge: 'C1', sessionId: session.id, lane: 'strict', kind: 'authentication' }, t0).ok).toBe(false);
    expect(svc.consumeChallenge({ challenge: 'C1', sessionId: session.id, lane: 'strict', kind: 'registration' }, t0).ok).toBe(true);
    expect(svc.consumeChallenge({ challenge: 'C1', sessionId: session.id, lane: 'strict', kind: 'registration' }, t0)).toEqual({ ok: false, reason: 'challenge already used' });
    svc.createChallenge({ sessionId: session.id, lane: 'strict', kind: 'registration', ttlSec: 10, challenge: 'C2' }, t0);
    expect(svc.consumeChallenge({ challenge: 'C2', sessionId: session.id, lane: 'strict', kind: 'registration' }, t0 + 11_000)).toEqual({ ok: false, reason: 'challenge expired' });
  });
});

describe('RateLimiter', () => {
  it('enforces a sliding window', () => {
    const rl = new RateLimiter(openDatabase(':memory:'));
    const rule = { max: 2, windowSec: 10 };
    expect(rl.consume('k', rule, 0).allowed).toBe(true);
    expect(rl.consume('k', rule, 1000).allowed).toBe(true);
    const d = rl.consume('k', rule, 2000);
    expect(d.allowed).toBe(false);
    expect(d.retryAfterSec).toBeGreaterThan(0);
    expect(rl.consume('k', rule, 10_001).allowed).toBe(true);
    expect(rl.consume('other', rule, 2000).allowed).toBe(true);
  });
});
