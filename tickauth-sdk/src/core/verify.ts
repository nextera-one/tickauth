import { getDefaultReplayGuard, ReplayGuard, type ReplayGuardStore } from "./replay-guard";
import { getCurrentTick, serializeProofPayload } from "./challenge";
import { createCapsule } from "./capsule";
import { verifyEd25519 } from "./crypto";
/**
 * TickAuth SDK - Proof Verification
 * ----------------------------------
 * Verify proofs with signature, window, and replay checks.
 */
import type { CapsuleType, ReplayScope, TickAuthClearance, TickAuthMode, TickAuthProof, VerifyResult } from "./types";

export interface VerifyOptions {
  /** Public key to verify against (hex). If not provided, verification will fail (never trust embedded key by default). */
  publicKeyHex?: string;
  /** Require external trusted key (default: true). If true and no publicKeyHex is provided, fail verification. */
  requireTrustedKey?: boolean;
  /** Replay guard instance. If not provided, uses default shared instance. */
  replayGuard?: ReplayGuard;
  /** Skip replay check (not recommended) */
  skipReplayCheck?: boolean;
  /** Expected action to enforce action-bound proofs */
  expectedAction?: string;
  /** Expected mode to enforce assurance mode policy */
  expectedMode?: TickAuthMode;
  /** Replay uniqueness scope (default: 'proof') */
  replayScope?: ReplayScope;
  /** Custom current tick (for testing) */
  currentTick?: number;
  /** Clearance duration in milliseconds (default: 60000 = 1 minute) */
  clearanceDurationMs?: number;
  /**
   * Async replay guard for distributed deployments (Redis-backed etc.).
   * Takes precedence over `replayGuard` if both are provided.
   */
  asyncReplayGuard?: ReplayGuardStore;
  /**
   * For PRESENCE mode step-up: the parent capsule ID to link this authorization to.
   * Include when authorizing a step-up action that requires an active session context.
   */
  presenceParentCapsuleId?: string;
  /**
   * When true and mode is PRESENCE, deny verification if no presenceParentCapsuleId is provided.
   * Enforces that every PRESENCE step-up is chained to an existing session capsule.
   */
  requireParentCapsule?: boolean;
  /** Capsule type for the resulting capsule (default: 'tickauth.authorization') */
  capsuleType?: CapsuleType;
  /** Capsule validity duration in ms — sets valid_until on the capsule (default: clearanceDurationMs) */
  capsuleValidityMs?: number;
  /** Device ID of the entity issuing/approving this capsule (e.g. mobile app device) */
  issuerDeviceId?: string;
  /** Device ID of the subject being authorized (e.g. browser device) */
  subjectDeviceId?: string;
  /** Scope/capabilities to embed in the capsule */
  scope?: string[];
  /** If true, the resulting capsule will be marked single_use */
  singleUse?: boolean;
}

function buildReplayKey(
  proof: TickAuthProof,
  replayScope: ReplayScope,
): string {
  const base = `${proof.challenge.id}|${proof.challenge.nonce}|${proof.challenge.action}|${proof.challenge.mode}`;
  if (replayScope === "nonce") {
    return `nonce|${proof.challenge.nonce}`;
  }

  if (replayScope === "challenge") {
    return `challenge|${base}`;
  }

  return `proof|${base}|${proof.tick}|${proof.sig.publicKeyHex}|${proof.sig.sigHex}`;
}

/**
 * Verify a TickAuth proof.
 *
 * Checks:
 * 1. Signature validity
 * 2. Tick is within window
 * 3. Nonce hasn't been used (replay protection)
 * 4. Clock drift is acceptable
 *
 * @param proof - The proof to verify
 * @param options - Verification options
 * @returns Verification result with clearance on success
 *
 * @example
 * ```ts
 * const result = await verifyProof(proof);
 * if (result.ok) {
 *   console.log('Authorized:', result.clearance);
 * }
 * ```
 */
export async function verifyProof(
  proof: TickAuthProof,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  if (
    !proof?.challenge ||
    !proof?.sig ||
    typeof proof.tick !== "number" ||
    !proof.signedAt
  ) {
    return {
      ok: false,
      error: "INVALID_PROOF",
      message: "Malformed proof payload",
    };
  }

  if (
    options.expectedAction &&
    proof.challenge.action !== options.expectedAction
  ) {
    const capsule = createCapsule({
      proof,
      status: "denied",
      reason: "ACTION_MISMATCH",
    });
    return {
      ok: false,
      error: "ACTION_MISMATCH",
      message: "Proof action does not match expected action",
      capsule,
      capsule_id: capsule.capsule_id,
    };
  }

  if (options.expectedMode && proof.challenge.mode !== options.expectedMode) {
    const capsule = createCapsule({
      proof,
      status: "denied",
      reason: "MODE_MISMATCH",
    });
    return {
      ok: false,
      error: "MODE_MISMATCH",
      message: "Proof mode does not match expected mode",
      capsule,
      capsule_id: capsule.capsule_id,
    };
  }

  // By default, require a trusted key (never trust embedded key unless explicitly allowed)
  const requireTrustedKey = options.requireTrustedKey !== false;
  const publicKeyHex = options.publicKeyHex;
  if (requireTrustedKey && !publicKeyHex) {
    return {
      ok: false,
      error: "INVALID_PROOF",
      message:
        "No trusted public key provided. Refusing to trust embedded key.",
    };
  }
  const replayGuard = options.replayGuard ?? getDefaultReplayGuard();
  const replayScope = options.replayScope ?? "proof";
  const currentTick = options.currentTick ?? getCurrentTick();
  const clearanceDurationMs = options.clearanceDurationMs ?? 60000;

  // 1. Check signature
  const message = serializeProofPayload(
    proof.challenge,
    proof.tick,
    proof.signedAt,
  );

  const sigValid = await verifyEd25519(
    message,
    proof.sig.sigHex,
    publicKeyHex ?? proof.sig.publicKeyHex,
  );
  if (!sigValid) {
    const capsule = createCapsule({
      proof,
      status: "denied",
      reason: "INVALID_SIGNATURE",
    });
    return {
      ok: false,
      error: "INVALID_SIGNATURE",
      message: "Signature verification failed",
      capsule,
      capsule_id: capsule.capsule_id,
    };
  }

  // 2. Check tick is within window
  const { window } = proof.challenge;
  const drift = window.maxDriftMs ?? 1000;

  if (proof.tick < window.tickStart - drift) {
    const capsule = createCapsule({
      proof,
      status: "expired",
      reason: "OUTSIDE_WINDOW_EARLY",
    });
    return {
      ok: false,
      error: "OUTSIDE_WINDOW",
      message: "Proof tick is before window start",
      capsule,
      capsule_id: capsule.capsule_id,
    };
  }

  if (proof.tick > window.tickEnd + drift) {
    const capsule = createCapsule({
      proof,
      status: "expired",
      reason: "OUTSIDE_WINDOW_LATE",
    });
    return {
      ok: false,
      error: "OUTSIDE_WINDOW",
      message: "Proof tick is after window end",
      capsule,
      capsule_id: capsule.capsule_id,
    };
  }

  // 3. Check current time is not too far from proof time
  const timeDiff = Math.abs(currentTick - proof.tick);
  if (timeDiff > window.tickEnd - window.tickStart + drift) {
    const capsule = createCapsule({
      proof,
      status: "denied",
      reason: "DRIFT_EXCEEDED",
      driftApplied: timeDiff,
    });
    return {
      ok: false,
      error: "DRIFT_EXCEEDED",
      message: "Clock drift between verifier and prover is too large",
      capsule,
      capsule_id: capsule.capsule_id,
    };
  }

  // 4. Check for replay
  if (!options.skipReplayCheck) {
    const replayKey = buildReplayKey(proof, replayScope);
    const isNewNonce = options.asyncReplayGuard
      ? await options.asyncReplayGuard.checkAndMark(replayKey)
      : replayGuard.check(replayKey);
    if (!isNewNonce) {
      const capsule = createCapsule({
        proof,
        status: "replay_rejected",
        reason: "NONCE_ALREADY_USED",
      });
      return {
        ok: false,
        error: "REPLAY_DETECTED",
        message: "This proof has already been used",
        capsule,
        capsule_id: capsule.capsule_id,
      };
    }
  }

  // 5. Enforce PRESENCE mode parent capsule requirement
  if (
    proof.challenge.mode === "PRESENCE" &&
    options.requireParentCapsule &&
    !options.presenceParentCapsuleId
  ) {
    const capsule = createCapsule({
      proof,
      status: "denied",
      reason: "MISSING_PARENT_CAPSULE",
    });
    return {
      ok: false,
      error: "POLICY_DENIED",
      message:
        "PRESENCE mode requires a parent capsule (active session context)",
      capsule,
      capsule_id: capsule.capsule_id,
    };
  }

  // 6. Create clearance (kept for backward compatibility)
  const clearance: TickAuthClearance = {
    granted: true,
    challengeId: proof.challenge.id,
    action: proof.challenge.action,
    mode: proof.challenge.mode,
    tick: currentTick,
    expiresAt: new Date(currentTick + clearanceDurationMs).toISOString(),
  };

  // 7. Create capsule evidence artifact
  const capsuleParents: string[] = [];
  if (options.presenceParentCapsuleId)
    capsuleParents.push(options.presenceParentCapsuleId);

  const capsule = createCapsule({
    proof,
    status: "approved",
    capsuleType: options.capsuleType,
    validFrom: new Date(currentTick).toISOString(),
    validUntil: new Date(
      currentTick + (options.capsuleValidityMs ?? clearanceDurationMs),
    ).toISOString(),
    issuerDeviceId: options.issuerDeviceId,
    subjectDeviceId: options.subjectDeviceId,
    scope: options.scope,
    singleUse: options.singleUse,
    parents: capsuleParents.length ? capsuleParents : undefined,
  });

  return {
    ok: true,
    clearance,
    capsule,
    capsule_id: capsule.capsule_id,
  };
}

/**
 * Quick check if a proof's tick is within its window.
 * Does not verify signature or check replay.
 */
export function isProofInWindow(
  proof: TickAuthProof,
  currentTick?: number,
): boolean {
  const tick = currentTick ?? getCurrentTick();
  const { window } = proof.challenge;
  const drift = window.maxDriftMs ?? 1000;

  return (
    proof.tick >= window.tickStart - drift &&
    proof.tick <= window.tickEnd + drift
  );
}
