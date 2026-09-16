/**
 * End-to-end API flows with the fixture authenticator (positive control) and untrusted shapes.
 */
import { describe, expect, it } from 'vitest';
import { createHarness, createSession, enroll, assertWith, redeem, SITE_A, SITE_B, DIGEST_B, FixtureCredential, TEST_RP_ID, TEST_ORIGIN } from '../helpers/testApp.js';

describe('first-use and returning-user flows (strict lane)', () => {
  it('first use: enroll trusted → fresh assertion → token → redeem → consumed', async () => {
    const h = await createHarness();
    const s = await createSession(h, { returnUrl: `${TEST_ORIGIN}/demo/complete` });
    const st0 = await h.http.json(`/verification-sessions/${s.id}`, { clientToken: s.clientToken });
    expect(st0.body.session.state).toBe('pending');
    const e = await enroll(h, s, { kind: 'full', ca: h.ca });
    expect(e.verify!.status).toBe(200);
    expect(e.verify!.body.enrolled).toBe(true);
    expect(e.verify!.body.meetsPolicy).toBe(true);
    expect(e.verify!.body.policy.evidence.chain.anchorLabel).toContain('FIXTURE');
    // Enrollment alone never approves.
    expect(e.verify!.body.sessionState).toBe('pending');
    expect(e.verify!.body.approvalToken).toBeUndefined();
    const a = await assertWith(h, s, e.cred);
    expect(a.verify!.body.approved).toBe(true);
    expect(a.verify!.body.approvalToken).toMatch(/^hvt_/);
    expect(a.verify!.body.returnUrl).toBe(`${TEST_ORIGIN}/demo/complete`);
    expect(a.verify!.body.sessionState).toBe('approved');
    const r = await redeem(h, s, a.verify!.body.approvalToken);
    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);
    expect(r.body.session.state).toBe('consumed');
    expect(r.body.assurance).toBe('credential-meets-configured-authenticator-policy');
  });

  it('returning use: previously enrolled trusted credential approves a new session with a fresh assertion', async () => {
    const h = await createHarness();
    const s1 = await createSession(h);
    const e = await enroll(h, s1, { kind: 'full', ca: h.ca });
    expect(e.verify!.body.meetsPolicy).toBe(true);
    const s2 = await createSession(h, { digest: DIGEST_B });
    const a = await assertWith(h, s2, e.cred);
    expect(a.verify!.body.approved).toBe(true);
    const r = await redeem(h, s2, a.verify!.body.approvalToken);
    expect(r.body.ok).toBe(true);
    // The token from s2 cannot be used for s1.
    const s1Again = await assertWith(h, s1, e.cred);
    expect(s1Again.verify!.body.approved).toBe(true);
    const cross = await redeem(h, s1, a.verify!.body.approvalToken);
    expect(cross.status).toBe(409);
  });

  it('demo site: submission digest binds the payload; redeem via the site backend accepts exactly once', async () => {
    const h = await createHarness();
    const sub = await h.http.json('/demo/api/submit', { body: { name: 'Ada', email: 'ada@example.com', message: 'hi' } });
    expect(sub.status).toBe(200);
    const url = new URL(sub.body.verifyUrl);
    const params = Object.fromEntries(url.hash.slice(1).split('&').map((kv) => kv.split('=').map(decodeURIComponent) as [string, string]));
    const s = { id: params.s!, clientToken: params.t!, action: 'contact-form:submit', digest: sub.body.submissionDigest, site: SITE_A };
    const e = await enroll(h, s, { kind: 'full', ca: h.ca });
    expect(e.verify!.body.meetsPolicy).toBe(true);
    const a = await assertWith(h, s, e.cred);
    expect(a.verify!.body.approved).toBe(true);
    const form = new URLSearchParams({ sessionId: s.id, approvalToken: a.verify!.body.approvalToken });
    const done = await h.app.request('/demo/complete', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    expect(done.status).toBe(200);
    expect(await done.text()).toContain('Submission accepted');
    const again = await h.app.request('/demo/complete', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    expect(again.status).toBe(409);
    const stored = await h.http.json(`/demo/api/submissions/${s.id}`);
    expect(stored.body.state).toBe('rejected'); // second attempt overwrote state; first was accepted
  });
});

describe('untrusted authenticators never obtain approval', () => {
  it('software self-attestation: library verifies, strict policy rejects, no token', async () => {
    const h = await createHarness();
    const s = await createSession(h);
    const e = await enroll(h, s, { kind: 'self' });
    expect(e.verify!.body.libraryVerified).toBe(true);
    expect(e.verify!.body.enrolled).toBe(true);
    expect(e.verify!.body.meetsPolicy).toBe(false);
    expect(e.verify!.body.policy.rejectionCodes).toContain('SELF_ATTESTATION');
    const a = await assertWith(h, s, e.cred);
    expect(a.verify!.body.verified).toBe(true);
    expect(a.verify!.body.approved).toBe(false);
    expect(a.verify!.body.approvalToken).toBeNull();
    expect(a.verify!.body.reasons.join(' ')).toContain('did not meet strict attestation policy');
    expect((await h.http.json(`/verification-sessions/${s.id}`, { site: SITE_A })).body.session.state).toBe('pending');
  });

  it('none attestation and unknown-root full attestation are rejected', async () => {
    const h = await createHarness();
    const s = await createSession(h);
    const none = await enroll(h, s, { kind: 'none' });
    expect(none.verify!.body.meetsPolicy).toBe(false);
    expect(none.verify!.body.policy.rejectionCodes).toContain('ATTESTATION_ABSENT');
    const unknownRoot = await enroll(h, s, { kind: 'full', ca: h.unlistedCa });
    expect(unknownRoot.verify!.body.meetsPolicy).toBe(false);
    expect(unknownRoot.verify!.body.policy.rejectionCodes).toContain('AAGUID_NOT_IN_METADATA');
  });

  it('new trusted enrollment does not convert a session approved-by-nothing: untrusted assertion still fails, trusted needs its own fresh assertion', async () => {
    const h = await createHarness();
    const s = await createSession(h);
    const soft = await enroll(h, s, { kind: 'self' });
    const a1 = await assertWith(h, s, soft.cred);
    expect(a1.verify!.body.approved).toBe(false);
    const hard = await enroll(h, s, { kind: 'full', ca: h.ca });
    expect(hard.verify!.body.meetsPolicy).toBe(true);
    expect(hard.verify!.body.sessionState).toBe('pending');
    // Untrusted credential still cannot approve after a trusted enrollment happened in the session.
    const a2 = await assertWith(h, s, soft.cred);
    expect(a2.verify!.body.approved).toBe(false);
    // Only a fresh assertion from the trusted credential approves.
    const a3 = await assertWith(h, s, hard.cred);
    expect(a3.verify!.body.approved).toBe(true);
  });

  it('diagnostic lane never mints tokens and its credentials cannot be used in the strict lane', async () => {
    const h = await createHarness();
    const o = await h.http.json('/diagnostics/registration/options', { body: {} });
    const cred = await FixtureCredential.create({ rpId: TEST_RP_ID, origin: TEST_ORIGIN });
    const reg = await cred.register(o.body.options, { kind: 'full', ca: h.ca });
    const v = await h.http.json('/diagnostics/registration/verify', { body: { response: reg } });
    expect(v.body.policy.trusted).toBe(true); // evidence is reported honestly…
    expect(v.body.approvalToken).toBeNull(); // …but nothing is minted
    const ao = await h.http.json('/diagnostics/authentication/options', { body: {} });
    const av = await h.http.json('/diagnostics/authentication/verify', { body: { response: await cred.assert(ao.body.options) } });
    expect(av.body.verified).toBe(true);
    expect(av.body.approved).toBe(false);
    expect(av.body.approvalToken).toBeNull();
    // Strict lane refuses the diagnostic credential and diagnostic challenges.
    const s = await createSession(h);
    const strict = await assertWith(h, s, cred);
    expect(strict.verify!.body.approved).toBe(false);
    expect(strict.verify!.body.reasons.join(' ')).toContain('diagnostic lane');
    const diagChallengeInStrict = await h.http.json(`/verification-sessions/${s.id}/authentication/verify`, { clientToken: s.clientToken, body: { response: await cred.assert((await h.http.json('/diagnostics/authentication/options', { body: {} })).body.options) } });
    expect(diagChallengeInStrict.body.error).toContain('different');
    expect(diagChallengeInStrict.body.approved).toBe(false);
  });

  it('a stored credential evaluated under an older policy version is not eligible', async () => {
    const h = await createHarness();
    const s = await createSession(h);
    const e = await enroll(h, s, { kind: 'full', ca: h.ca });
    h.deps.db.prepare('UPDATE credentials SET policy_version = ? WHERE id = ?').run('strict-v0', e.cred.idB64);
    const a = await assertWith(h, s, e.cred);
    expect(a.verify!.body.approved).toBe(false);
    expect(a.verify!.body.reasons.join(' ')).toContain('policy strict-v0');
  });
});

describe('site isolation', () => {
  it('a site cannot read or redeem another site\'s session', async () => {
    const h = await createHarness();
    const s = await createSession(h, { site: SITE_A });
    expect((await h.http.json(`/verification-sessions/${s.id}`, { site: SITE_B })).status).toBe(403);
    const e = await enroll(h, s, { kind: 'full', ca: h.ca });
    const a = await assertWith(h, s, e.cred);
    expect((await redeem(h, s, a.verify!.body.approvalToken, { site: SITE_B })).status).toBe(409);
    expect((await redeem(h, s, a.verify!.body.approvalToken)).status).toBe(200);
  });
});
