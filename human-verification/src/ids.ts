import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export function base64url(bytes: Uint8Array | Buffer): string {
  return Buffer.from(bytes).toString('base64url');
}

/** 256-bit random identifier, base64url, optionally prefixed for log readability. */
export function randomId(prefix = ''): string {
  return prefix + base64url(randomBytes(32));
}

/** High-entropy opaque bearer secret (256 bits). Only its hash is stored. */
export function randomSecret(prefix: string): string {
  return `${prefix}_${base64url(randomBytes(32))}`;
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

export function sha256Base64url(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('base64url');
}

export function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    // Compare against itself to keep timing roughly constant, then fail.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

export function nowMs(): number {
  return Date.now();
}
