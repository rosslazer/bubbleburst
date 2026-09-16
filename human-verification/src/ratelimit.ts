/**
 * Sliding-window rate limiter backed by SQLite.
 *
 * Prototype control only. Network (IP) limits affect everyone behind a shared address; credential
 * limits can be sidestepped by enrolling a fresh credential. Neither establishes uniqueness.
 */
import type { DB } from './db.js';
import type { RateLimitRule } from './config.js';

export interface RateDecision {
  allowed: boolean;
  remaining: number;
  retryAfterSec: number;
}

export class RateLimiter {
  private readonly consumeTx: (key: string, rule: RateLimitRule, now: number) => RateDecision;

  constructor(private readonly db: DB) {
    const count = db.prepare('SELECT COUNT(*) AS n FROM rate_events WHERE key = ? AND ts > ?');
    const insert = db.prepare('INSERT INTO rate_events(key, ts) VALUES (?, ?)');
    const prune = db.prepare('DELETE FROM rate_events WHERE key = ? AND ts <= ?');
    const oldest = db.prepare('SELECT MIN(ts) AS t FROM rate_events WHERE key = ? AND ts > ?');
    this.consumeTx = db.transaction((key: string, rule: RateLimitRule, now: number): RateDecision => {
      const windowStart = now - rule.windowSec * 1000;
      prune.run(key, windowStart);
      const { n } = count.get(key, windowStart) as { n: number };
      if (n >= rule.max) {
        const { t } = oldest.get(key, windowStart) as { t: number | null };
        const retryAfterSec = t ? Math.max(1, Math.ceil((t + rule.windowSec * 1000 - now) / 1000)) : rule.windowSec;
        return { allowed: false, remaining: 0, retryAfterSec };
      }
      insert.run(key, now);
      return { allowed: true, remaining: rule.max - n - 1, retryAfterSec: 0 };
    });
  }

  /** Atomically records one event for `key` if the rule permits it. */
  consume(key: string, rule: RateLimitRule, now = Date.now()): RateDecision {
    return this.consumeTx(key, rule, now);
  }
}
