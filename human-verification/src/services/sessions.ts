/**
 * Verification sessions, challenges and approval tokens.
 *
 * State machine: pending → approved → consumed, with expired/rejected as terminal outcomes.
 * Every transition is an explicit method here; route handlers never write session state directly.
 */
import type { DB, SessionRow, ChallengeRow, TokenRow, Lane } from '../db.js';
import { randomId, randomSecret, sha256Hex, constantTimeEqual } from '../ids.js';

export interface CreateSessionInput {
  siteId: string;
  action: string;
  submissionDigest: string;
  clientIp: string | null;
  returnUrl: string | null;
  ttlSec: number;
}

export interface RedeemInput {
  siteId: string;
  sessionId: string;
  action: string;
  submissionDigest: string;
  token: string;
}

export type RedeemFailure = 'TOKEN_UNKNOWN' | 'TOKEN_ALREADY_CONSUMED' | 'TOKEN_EXPIRED' | 'BINDING_MISMATCH' | 'SESSION_NOT_APPROVED';

export type RedeemOutcome = { ok: true; session: SessionRow; token: TokenRow } | { ok: false; reason: RedeemFailure };

class SessionNotApprovedError extends Error {}

export class SessionService {
  constructor(private readonly db: DB) {}

  create(input: CreateSessionInput, now = Date.now()): { session: SessionRow; clientToken: string } {
    const id = randomId('vs_');
    const clientToken = randomSecret('hvc');
    const row: SessionRow = {
      id,
      site_id: input.siteId,
      action: input.action,
      submission_digest: input.submissionDigest,
      state: 'pending',
      client_token_hash: sha256Hex(clientToken),
      created_at: now,
      expires_at: now + input.ttlSec * 1000,
      approved_at: null,
      consumed_at: null,
      rejected_reason: null,
      approving_credential_id: null,
      approval_token_id: null,
      last_enrolled_credential_id: null,
      client_ip: input.clientIp,
      return_url: input.returnUrl,
    };
    this.db
      .prepare(
        `INSERT INTO verification_sessions (id, site_id, action, submission_digest, state, client_token_hash, created_at, expires_at,
          approved_at, consumed_at, rejected_reason, approving_credential_id, approval_token_id, last_enrolled_credential_id, client_ip, return_url)
         VALUES (@id, @site_id, @action, @submission_digest, @state, @client_token_hash, @created_at, @expires_at,
          @approved_at, @consumed_at, @rejected_reason, @approving_credential_id, @approval_token_id, @last_enrolled_credential_id, @client_ip, @return_url)`,
      )
      .run(row);
    return { session: row, clientToken };
  }

  /** Loads a session and applies expiry lazily. */
  get(id: string, now = Date.now()): SessionRow | undefined {
    const row = this.db.prepare('SELECT * FROM verification_sessions WHERE id = ?').get(id) as SessionRow | undefined;
    if (!row) return undefined;
    if (row.state === 'pending' && row.expires_at <= now) {
      this.db.prepare(`UPDATE verification_sessions SET state = 'expired' WHERE id = ? AND state = 'pending'`).run(id);
      row.state = 'expired';
    }
    return row;
  }

  clientAuthorized(session: SessionRow, clientToken: string | undefined): boolean {
    if (!clientToken) return false;
    return constantTimeEqual(session.client_token_hash, sha256Hex(clientToken));
  }

  reject(id: string, reason: string): void {
    this.db.prepare(`UPDATE verification_sessions SET state = 'rejected', rejected_reason = ? WHERE id = ? AND state = 'pending'`).run(reason, id);
  }

  noteEnrollment(id: string, credentialId: string): void {
    this.db.prepare('UPDATE verification_sessions SET last_enrolled_credential_id = ? WHERE id = ?').run(credentialId, id);
  }

  /**
   * pending → approved. Issues the one-time approval token bound to site/session/action/digest.
   * Returns null if the session was not pending (a session never gets a second token).
   */
  approve(sessionId: string, credentialId: string, tokenTtlSec: number, now = Date.now()): { token: string; expiresAt: number } | null {
    const tx = this.db.transaction(() => {
      const session = this.get(sessionId, now);
      if (!session || session.state !== 'pending') return null;
      const token = randomSecret('hvt');
      const tokenId = randomId('tk_');
      const expiresAt = now + tokenTtlSec * 1000;
      this.db
        .prepare(
          `INSERT INTO approval_tokens (id, token_hash, session_id, site_id, action, submission_digest, credential_id, issued_at, expires_at, consumed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
        )
        .run(tokenId, sha256Hex(token), session.id, session.site_id, session.action, session.submission_digest, credentialId, now, expiresAt);
      const res = this.db
        .prepare(`UPDATE verification_sessions SET state = 'approved', approved_at = ?, approving_credential_id = ?, approval_token_id = ? WHERE id = ? AND state = 'pending'`)
        .run(now, credentialId, tokenId, session.id);
      if (res.changes !== 1) throw new Error('session state changed concurrently');
      return { token, expiresAt };
    });
    return tx();
  }

  /**
   * Atomic one-time redemption. Exactly one caller can succeed for a given token, and only when
   * site, session, action and digest all match the values the token was minted for. A mismatched
   * attempt does not consume the token.
   */
  redeem(input: RedeemInput, now = Date.now()): RedeemOutcome {
    const tokenHash = sha256Hex(input.token);
    const tx = this.db.transaction((): RedeemOutcome => {
      const existing = this.db.prepare('SELECT * FROM approval_tokens WHERE token_hash = ?').get(tokenHash) as TokenRow | undefined;
      if (!existing) return { ok: false, reason: 'TOKEN_UNKNOWN' };
      if (
        existing.site_id !== input.siteId ||
        existing.session_id !== input.sessionId ||
        existing.action !== input.action ||
        existing.submission_digest !== input.submissionDigest
      ) {
        return { ok: false, reason: 'BINDING_MISMATCH' };
      }
      if (existing.consumed_at !== null) return { ok: false, reason: 'TOKEN_ALREADY_CONSUMED' };
      if (existing.expires_at <= now) return { ok: false, reason: 'TOKEN_EXPIRED' };
      const res = this.db
        .prepare(
          `UPDATE approval_tokens SET consumed_at = ?
           WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?
             AND site_id = ? AND session_id = ? AND action = ? AND submission_digest = ?`,
        )
        .run(now, tokenHash, now, input.siteId, input.sessionId, input.action, input.submissionDigest);
      if (res.changes !== 1) return { ok: false, reason: 'TOKEN_ALREADY_CONSUMED' };
      const sres = this.db
        .prepare(`UPDATE verification_sessions SET state = 'consumed', consumed_at = ? WHERE id = ? AND state = 'approved'`)
        .run(now, input.sessionId);
      if (sres.changes !== 1) throw new SessionNotApprovedError();
      const session = this.db.prepare('SELECT * FROM verification_sessions WHERE id = ?').get(input.sessionId) as SessionRow;
      const token = this.db.prepare('SELECT * FROM approval_tokens WHERE token_hash = ?').get(tokenHash) as TokenRow;
      return { ok: true, session, token };
    });
    try {
      return tx();
    } catch (err) {
      if (err instanceof SessionNotApprovedError) return { ok: false, reason: 'SESSION_NOT_APPROVED' };
      throw err;
    }
  }

  // ---- challenges -------------------------------------------------------------------------

  createChallenge(opts: { sessionId: string | null; lane: Lane; kind: ChallengeRow['kind']; ttlSec: number; challenge: string }, now = Date.now()): ChallengeRow {
    const row: ChallengeRow = {
      id: randomId('ch_'),
      session_id: opts.sessionId,
      lane: opts.lane,
      kind: opts.kind,
      challenge: opts.challenge,
      created_at: now,
      expires_at: now + opts.ttlSec * 1000,
      consumed_at: null,
    };
    this.db
      .prepare('INSERT INTO challenges (id, session_id, lane, kind, challenge, created_at, expires_at, consumed_at) VALUES (@id, @session_id, @lane, @kind, @challenge, @created_at, @expires_at, @consumed_at)')
      .run(row);
    return row;
  }

  /**
   * Atomically consumes the challenge if it exists, is unexpired, unconsumed, and bound to the given
   * session/lane/ceremony. The challenge value is taken from the signed clientDataJSON, so a response
   * built for another session (or a replay) fails here before any signature work.
   */
  consumeChallenge(opts: { challenge: string; sessionId: string | null; lane: Lane; kind: ChallengeRow['kind'] }, now = Date.now()): { ok: true; row: ChallengeRow } | { ok: false; reason: string } {
    const tx = this.db.transaction(() => {
      const row = this.db.prepare('SELECT * FROM challenges WHERE challenge = ?').get(opts.challenge) as ChallengeRow | undefined;
      if (!row) return { ok: false as const, reason: 'challenge unknown' };
      if (row.session_id !== opts.sessionId) return { ok: false as const, reason: 'challenge bound to a different session' };
      if (row.lane !== opts.lane) return { ok: false as const, reason: 'challenge bound to a different lane' };
      if (row.kind !== opts.kind) return { ok: false as const, reason: 'challenge issued for a different ceremony' };
      if (row.consumed_at !== null) return { ok: false as const, reason: 'challenge already used' };
      if (row.expires_at <= now) return { ok: false as const, reason: 'challenge expired' };
      const res = this.db.prepare('UPDATE challenges SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL').run(now, row.id);
      if (res.changes !== 1) return { ok: false as const, reason: 'challenge already used' };
      return { ok: true as const, row: { ...row, consumed_at: now } };
    });
    return tx();
  }
}
