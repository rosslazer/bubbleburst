import type { DB, CredentialRow, Lane } from '../db.js';
import type { PolicyResult } from '../policy/attestationPolicy.js';

export interface StoreCredentialInput {
  id: string;
  lane: Lane;
  publicKey: Uint8Array;
  counter: number;
  transports: string[] | undefined;
  aaguid: string;
  fmt: string;
  userHandle: string;
  backupEligible: boolean;
  backupState: boolean;
  uvAtRegistration: boolean;
  policy: PolicyResult;
  enrolledSessionId: string | null;
}

export class CredentialService {
  constructor(private readonly db: DB) {}

  get(id: string): CredentialRow | undefined {
    return this.db.prepare('SELECT * FROM credentials WHERE id = ?').get(id) as CredentialRow | undefined;
  }

  /**
   * Stores the verified public key together with the policy verdict. Untrusted credentials are kept
   * (policy_trusted = 0) so a returning visitor gets an accurate explanation instead of an "unknown
   * credential" error. They can never approve a session. Diagnostic-lane credentials are never trusted.
   */
  store(input: StoreCredentialInput, now = Date.now()): CredentialRow {
    const row: CredentialRow = {
      id: input.id,
      lane: input.lane,
      public_key: Buffer.from(input.publicKey),
      counter: input.counter,
      transports: input.transports ? JSON.stringify(input.transports) : null,
      aaguid: input.aaguid,
      fmt: input.fmt,
      user_handle: input.userHandle,
      backup_eligible: input.backupEligible ? 1 : 0,
      backup_state: input.backupState ? 1 : 0,
      uv_at_registration: input.uvAtRegistration ? 1 : 0,
      policy_trusted: input.lane === 'strict' && input.policy.trusted ? 1 : 0,
      policy_version: input.policy.policyVersion,
      policy_result: JSON.stringify(input.policy),
      metadata_source: input.policy.evidence.metadata.source,
      enrolled_session_id: input.enrolledSessionId,
      created_at: now,
      last_used_at: null,
    };
    this.db
      .prepare(
        `INSERT INTO credentials (id, lane, public_key, counter, transports, aaguid, fmt, user_handle, backup_eligible, backup_state,
           uv_at_registration, policy_trusted, policy_version, policy_result, metadata_source, enrolled_session_id, created_at, last_used_at)
         VALUES (@id, @lane, @public_key, @counter, @transports, @aaguid, @fmt, @user_handle, @backup_eligible, @backup_state,
           @uv_at_registration, @policy_trusted, @policy_version, @policy_result, @metadata_source, @enrolled_session_id, @created_at, @last_used_at)`,
      )
      .run(row);
    return row;
  }

  updateCounter(id: string, counter: number, now = Date.now()): void {
    this.db.prepare('UPDATE credentials SET counter = ?, last_used_at = ? WHERE id = ?').run(counter, now, id);
  }
}
