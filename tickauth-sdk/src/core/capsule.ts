/**
 * TickAuth SDK - Capsule Creation
 * ---------------------------------
 * Creates content-addressed Capsule evidence artifacts from TickAuth verifications.
 *
 * A Capsule is the canonical output of every TickAuth authorization decision.
 * Its ID is derived from the content hash (blake3), making it self-verifiable.
 *
 * capsule_id = "cps_b3_" + blake3(canonical_capsule_json_without_id)
 */

import { blake3 } from '@noble/hashes/blake3';
import { bytesToHex } from '@noble/hashes/utils';
import type {
  TickAuthProof,
  TickAuthCapsule,
  CapsuleStatus,
  TickAuthMode,
} from './types';

/**
 * Canonical JSON serialization for hashing.
 * Keys are sorted recursively to ensure deterministic output.
 */
function canonicalize(obj: unknown): string {
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  if (obj !== null && typeof obj === 'object') {
    const sorted = Object.keys(obj as object)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize((obj as Record<string, unknown>)[k]));
    return '{' + sorted.join(',') + '}';
  }
  return JSON.stringify(obj);
}

/**
 * Compute blake3 content-addressed capsule ID.
 * The ID is derived from the capsule body (without the capsule_id field itself).
 */
function computeCapsuleId(body: Omit<TickAuthCapsule, 'capsule_id'>): string {
  const canonical = canonicalize(body);
  const hash = blake3(new TextEncoder().encode(canonical));
  return 'cps_b3_' + bytesToHex(hash).slice(0, 32);
}

/**
 * Options for creating a capsule from an approved proof.
 */
export interface CreateCapsuleOptions {
  /** The signed proof that was verified */
  proof: TickAuthProof;
  /** Verification decision */
  status: CapsuleStatus;
  /** Denial reason (for non-approved outcomes) */
  reason?: string;
  /** Clock drift applied during verification (ms) */
  driftApplied?: number;
  /** Issuer URI (e.g. "tickauth://auth.example") */
  issuer?: string;
  /** Subject identifier override (defaults to proof.challenge.sub) */
  subject?: string;
  /** Parent capsule IDs (for authorization chain tracking) */
  parents?: string[];
}

/**
 * Create a TickAuth Capsule from a verification result.
 *
 * A Capsule is created for every verification outcome — approved, denied,
 * expired, or replay-rejected. This ensures every authorization event
 * produces a portable, verifiable evidence artifact.
 *
 * The capsule_id is content-addressed (blake3 of canonical JSON),
 * making Capsules self-verifiable without querying the issuing server.
 *
 * @example
 * ```ts
 * const result = await verifyProof(proof, { publicKeyHex: trustedKey });
 * if (result.capsule) {
 *   // Store result.capsule, return result.capsule_id to client
 *   console.log('Capsule ID:', result.capsule_id);
 * }
 * ```
 */
export function createCapsule(options: CreateCapsuleOptions): TickAuthCapsule {
  const { proof, status, reason, driftApplied = 0, issuer, parents } = options;
  const now = new Date().toISOString();

  const subject = options.subject ?? proof.challenge.sub;

  // Build the capsule body (without capsule_id — will be computed from this)
  const body: Omit<TickAuthCapsule, 'capsule_id'> = {
    capsule_version: 1,
    capsule_type: 'tickauth.authorization',
    ...(subject ? { subject } : {}),
    intent: {
      action: proof.challenge.action,
    },
    tick_index: proof.tick,
    ...(proof.challenge.tickTps ? { tick_tps: proof.challenge.tickTps } : {}),
    ...(proof.challenge.tickProfile ? { tick_profile: proof.challenge.tickProfile } : {}),
    nonce: proof.challenge.nonce,
    challenge_id: proof.challenge.id,
    mode: proof.challenge.mode as TickAuthMode,
    verification: {
      status,
      ...(reason ? { reason } : {}),
      ...(driftApplied !== 0 ? { drift_applied: driftApplied } : {}),
    },
    ...(issuer ? { issuer } : {}),
    issued_at: now,
    ...(parents?.length ? { parents } : {}),
  };

  const capsule_id = computeCapsuleId(body);

  return { capsule_id, ...body };
}

/**
 * Verify that a capsule's ID matches its content hash.
 * This proves the capsule has not been tampered with.
 *
 * Note: does not verify the cryptographic signature — use verifyCapsuleSignature for that.
 */
export function verifyCapsuleIntegrity(capsule: TickAuthCapsule): boolean {
  const { capsule_id, ...body } = capsule;
  const expected = computeCapsuleId(body);
  return capsule_id === expected;
}
