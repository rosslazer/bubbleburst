/**
 * Persistent storage (SQLite via better-sqlite3).
 *
 * Only public credential material, policy verdicts and opaque-token hashes are stored. No private
 * keys, no biometric data, no raw bearer secrets.
 */
import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export type SessionState = 'pending' | 'approved' | 'consumed' | 'expired' | 'rejected';
export type Lane = 'strict' | 'diagnostic';

export interface SessionRow {
  id: string;
  site_id: string;
  action: string;
  submission_digest: string;
  state: SessionState;
  client_token_hash: string;
  created_at: number;
  expires_at: number;
  approved_at: number | null;
  consumed_at: number | null;
  rejected_reason: string | null;
  approving_credential_id: string | null;
  approval_token_id: string | null;
  last_enrolled_credential_id: string | null;
  client_ip: string | null;
  return_url: string | null;
}

export interface ChallengeRow {
  id: string;
  session_id: string | null;
  lane: Lane;
  kind: 'registration' | 'authentication';
  challenge: string;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
}

export interface CredentialRow {
  id: string;
  lane: Lane;
  public_key: Buffer;
  counter: number;
  transports: string | null;
  aaguid: string;
  fmt: string;
  user_handle: string;
  backup_eligible: number;
  backup_state: number;
  uv_at_registration: number;
  policy_trusted: number;
  policy_version: string;
  policy_result: string;
  metadata_source: string | null;
  enrolled_session_id: string | null;
  created_at: number;
  last_used_at: number | null;
}

export interface TokenRow {
  id: string;
  token_hash: string;
  session_id: string;
  site_id: string;
  action: string;
  submission_digest: string;
  credential_id: string;
  issued_at: number;
  expires_at: number;
  consumed_at: number | null;
}

export interface DiagnosticRunRow {
  id: string;
  created_at: number;
  kind: string;
  evidence: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS verification_sessions (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  action TEXT NOT NULL,
  submission_digest TEXT NOT NULL,
  state TEXT NOT NULL,
  client_token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_at INTEGER,
  consumed_at INTEGER,
  rejected_reason TEXT,
  approving_credential_id TEXT,
  approval_token_id TEXT,
  last_enrolled_credential_id TEXT,
  client_ip TEXT,
  return_url TEXT
);
CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  session_id TEXT,
  lane TEXT NOT NULL,
  kind TEXT NOT NULL,
  challenge TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS challenges_session ON challenges(session_id, kind);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  lane TEXT NOT NULL,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT,
  aaguid TEXT NOT NULL,
  fmt TEXT NOT NULL,
  user_handle TEXT NOT NULL,
  backup_eligible INTEGER NOT NULL,
  backup_state INTEGER NOT NULL,
  uv_at_registration INTEGER NOT NULL,
  policy_trusted INTEGER NOT NULL,
  policy_version TEXT NOT NULL,
  policy_result TEXT NOT NULL,
  metadata_source TEXT,
  enrolled_session_id TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS approval_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  session_id TEXT NOT NULL UNIQUE,
  site_id TEXT NOT NULL,
  action TEXT NOT NULL,
  submission_digest TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS rate_events (
  key TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_events_key_ts ON rate_events(key, ts);
CREATE TABLE IF NOT EXISTS diagnostic_runs (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  kind TEXT NOT NULL,
  evidence TEXT NOT NULL
);
-- Demo relying site's own storage (logically a separate system; co-located for the prototype).
CREATE TABLE IF NOT EXISTS demo_submissions (
  session_id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  submission_digest TEXT NOT NULL,
  payload TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  accepted_at INTEGER,
  redeem_result TEXT
);
`;

export type DB = Database.Database;

export function openDatabase(path: string): DB {
  if (path !== ':memory:') {
    mkdirSync(dirname(path), { recursive: true });
  }
  const db = new Database(path);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  return db;
}
