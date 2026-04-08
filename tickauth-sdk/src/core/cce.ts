/**
 * TickAuth CCE — Capsule-Carried Encryption Extensions
 *
 * Extends TickAuth with CCE-specific challenge and capsule issuance
 * for AXIS protocol integration.
 *
 * CCE capsules bind:
 * - Subject identity (sub + kid)
 * - Intent (action being authorized)
 * - Audience (AXIS service identity)
 * - TPS window (temporal bounds)
 * - Policy hash (Digital Fabric Law)
 * - Capsule nonce (anti-replay)
 */
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { ulid } from "ulid";

import { getCurrentTick, serializeProofPayload } from "./challenge";
import { generateNonce, signEd25519, verifyEd25519 } from "./crypto";
import type { TickAuthChallenge, TickAuthIdentity, TickAuthMode, TickAuthProof, TickWindow } from "./types";

// ============================================================================
// CCE Protocol Version
// ============================================================================

export const CCE_VERSION = "cce-v1" as const;

// ============================================================================
// CCE Challenge Types
// ============================================================================

/**
 * Options for creating a CCE-bound challenge.
 */
export interface CceChallengeOptions {
  /** Subject / actor identity */
  sub: string;
  /** Client key identifier */
  kid: string;
  /** Intent being authorized */
  intent: string;
  /** AXIS audience (service identity) */
  audience: string;
  /** Verification mode */
  mode: TickAuthMode;
  /** Window duration in milliseconds (default: 30000) */
  windowMs?: number;
  /** Relying party */
  rp?: string;
  /** Requested scope */
  scope?: string[];
  /** Requested constraints */
  constraints?: CceCapsuleConstraints;
  /** Policy hash (if Digital Fabric Law is used) */
  policyHash?: string;
  /** TPS tick index (optional) */
  tickIndex?: number;
  /** TPS human-readable coordinate */
  tickTps?: string;
  /** TPS profile */
  tickProfile?: string;
}

export interface CceCapsuleConstraints {
  max_payload_bytes?: number;
  ip_allow?: string[];
  device_allow?: string[];
  country_allow?: string[];
}

/**
 * CCE-enhanced challenge with audience and intent binding.
 */
export interface CceChallenge extends TickAuthChallenge {
  /** CCE protocol version */
  cce_ver: typeof CCE_VERSION;
  /** Bound intent */
  cce_intent: string;
  /** AXIS audience */
  cce_audience: string;
  /** Client key id */
  cce_kid: string;
  /** Requested scope */
  cce_scope?: string[];
  /** Requested constraints */
  cce_constraints?: CceCapsuleConstraints;
  /** Policy hash */
  cce_policy_hash?: string;
}

/**
 * Signed CCE challenge.
 * TickAuth signs this payload so clients can verify challenge authenticity
 * before producing presence proofs.
 */
export interface CceSignedChallenge {
  challenge: CceChallenge;
  issuer_sig: CceSignature;
}

// ============================================================================
// CCE Capsule Claims (issued by TickAuth, verified by AXIS)
// ============================================================================

export interface CceSignature {
  alg: "EdDSA";
  kid: string;
  value: string; // hex
}

/**
 * CCE Capsule Claims — the core authority token.
 * Issued by TickAuth after successful proof verification.
 * Verified by AXIS before request processing.
 */
export interface CceCapsuleClaims {
  /** Content-addressed capsule identifier */
  capsule_id: string;
  /** Protocol version */
  ver: typeof CCE_VERSION;
  /** Subject / actor identity */
  sub: string;
  /** Client key identifier */
  kid: string;
  /** Bound intent */
  intent: string;
  /** AXIS audience (service identity) */
  aud: string;
  /** TPS window start (Unix ms) */
  tps_from: number;
  /** TPS window end (Unix ms) */
  tps_to: number;
  /** Capsule nonce (hex) */
  capsule_nonce: string;
  /** Originating challenge ID */
  challenge_id: string;
  /** Content hash of the validated proof payload */
  proof_hash?: string;
  /** Policy hash */
  policy_hash?: string;
  /** Issued at (Unix seconds) */
  iat: number;
  /** Expires at (Unix seconds) */
  exp: number;
  /** Usage mode */
  mode: "SINGLE_USE" | "SESSION";
  /** Scope capabilities */
  scope?: string[];
  /** Constraints */
  constraints?: CceCapsuleConstraints;
  /** TickAuth issuer signature */
  issuer_sig: CceSignature;
}

// ============================================================================
// CCE Challenge Creation
// ============================================================================

/**
 * Create a CCE-bound challenge.
 * Extends standard TickAuth challenge with intent, audience, and key binding.
 */
export function createCceChallenge(options: CceChallengeOptions): CceChallenge {
  if (!options.sub?.trim())
    throw new Error("createCceChallenge: sub is required");
  if (!options.kid?.trim())
    throw new Error("createCceChallenge: kid is required");
  if (!options.intent?.trim())
    throw new Error("createCceChallenge: intent is required");
  if (!options.audience?.trim())
    throw new Error("createCceChallenge: audience is required");
  if (
    !Number.isFinite(options.windowMs ?? 30000) ||
    (options.windowMs ?? 30000) <= 0
  ) {
    throw new Error("createCceChallenge: windowMs must be a positive number");
  }

  const now = getCurrentTick();
  const windowMs = options.windowMs ?? 30000;
  const startTick = options.tickIndex ?? now;

  const window: TickWindow = {
    tickStart: startTick,
    tickEnd: startTick + windowMs,
    maxDriftMs: 1000,
  };

  if (options.tickTps) {
    window.tpsStart = options.tickTps;
    window.tpsEnd = options.tickTps;
  }

  return {
    v: 1,
    id: ulid(),
    action: options.intent,
    mode: options.mode,
    window,
    nonce: generateNonce(32),
    iat: new Date(now).toISOString(),
    ...(options.rp ? { rp: options.rp } : {}),
    sub: options.sub,
    ...(options.tickIndex ? { tickIndex: options.tickIndex } : {}),
    ...(options.tickTps ? { tickTps: options.tickTps } : {}),
    ...(options.tickProfile ? { tickProfile: options.tickProfile } : {}),

    // CCE-specific fields
    cce_ver: CCE_VERSION,
    cce_intent: options.intent,
    cce_audience: options.audience,
    cce_kid: options.kid,
    ...(options.scope?.length ? { cce_scope: options.scope } : {}),
    ...(options.constraints ? { cce_constraints: options.constraints } : {}),
    ...(options.policyHash ? { cce_policy_hash: options.policyHash } : {}),
  };
}

/**
 * Build the signing payload for CCE challenges.
 */
function buildChallengeSignPayload(challenge: CceChallenge): Uint8Array {
  return new TextEncoder().encode(canonicalizeCcePayload(challenge));
}

/**
 * Sign a CCE challenge with TickAuth issuer key.
 */
export async function signCceChallenge(
  challenge: CceChallenge,
  issuerIdentity: TickAuthIdentity,
): Promise<CceSignedChallenge> {
  const signPayload = buildChallengeSignPayload(challenge);
  const value = await signEd25519(signPayload, issuerIdentity.privateKeyHex);
  return {
    challenge,
    issuer_sig: {
      alg: "EdDSA",
      kid: issuerIdentity.kid ?? "tickauth-issuer",
      value,
    },
  };
}

/**
 * Verify a signed CCE challenge using TickAuth issuer public key.
 */
export async function verifyCceChallengeSignature(
  signedChallenge: CceSignedChallenge,
  issuerPublicKeyHex: string,
): Promise<boolean> {
  const signPayload = buildChallengeSignPayload(signedChallenge.challenge);
  return verifyEd25519(
    signPayload,
    signedChallenge.issuer_sig.value,
    issuerPublicKeyHex,
  );
}

// ============================================================================
// CCE Capsule Issuance
// ============================================================================

/**
 * Canonical JSON for deterministic hashing.
 */
export function canonicalizeCcePayload(obj: unknown): string {
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalizeCcePayload).join(",") + "]";
  }
  if (obj !== null && typeof obj === "object") {
    const sorted = Object.keys(obj as object)
      .sort()
      .map(
        (k) =>
          JSON.stringify(k) +
          ":" +
          canonicalizeCcePayload((obj as Record<string, unknown>)[k]),
      );
    return "{" + sorted.join(",") + "}";
  }
  return JSON.stringify(obj);
}

/**
 * Compute content-addressed capsule ID from claims (excluding capsule_id and issuer_sig).
 */
function computeCceCapsuleId(
  claims: Omit<CceCapsuleClaims, "capsule_id" | "issuer_sig">,
): string {
  const canonical = canonicalizeCcePayload(claims);
  const hash = blake3(new TextEncoder().encode(canonical));
  return "cce_b3_" + bytesToHex(hash).slice(0, 32);
}

/**
 * Build the signing payload for capsule claims.
 * Signed by TickAuth private key to authorize the capsule.
 */
function buildCapsuleSignPayload(
  claims: Omit<CceCapsuleClaims, "issuer_sig">,
): Uint8Array {
  return new TextEncoder().encode(canonicalizeCcePayload(claims));
}

/**
 * Hash a proof into a short content-addressed identifier.
 * This hash is embedded in capsules to bind issued authority to one exact proof.
 */
export function hashCceProof(proof: TickAuthProof): string {
  const canonical = canonicalizeCcePayload(proof);
  const hash = blake3(new TextEncoder().encode(canonical));
  return "prf_b3_" + bytesToHex(hash).slice(0, 32);
}

export interface VerifyCceProofOptions {
  /**
   * Trusted subject key from your identity registry.
   * When provided, proof signatures must verify against this key.
   */
  trustedSubjectPublicKeyHex?: string;
  /**
   * If true and trustedSubjectPublicKeyHex is missing, verification fails.
   * Default: false (uses proof-embedded key when trusted key is absent).
   */
  requireTrustedSubjectKey?: boolean;
  /**
   * Tick source override (ms) for testing/distributed clock control.
   */
  currentTickMs?: number;
}

export interface VerifyCceProofResult {
  ok: boolean;
  code?:
    | "MALFORMED_PROOF"
    | "CHALLENGE_MISMATCH"
    | "SUBJECT_MISMATCH"
    | "KID_MISMATCH"
    | "INVALID_SIGNATURE"
    | "OUTSIDE_WINDOW"
    | "CHALLENGE_EXPIRED"
    | "CHALLENGE_NOT_YET_VALID"
    | "MISSING_TRUSTED_SUBJECT_KEY";
  message?: string;
  proofHash?: string;
}

/**
 * Validate a proof against one exact CCE challenge.
 * This enforces intent/audience/kid/time binding before capsule issuance.
 */
export async function verifyCceProofForChallenge(
  proof: TickAuthProof,
  challenge: CceChallenge,
  options: VerifyCceProofOptions = {},
): Promise<VerifyCceProofResult> {
  if (
    !proof?.challenge ||
    !proof?.sig?.sigHex ||
    !proof?.sig?.publicKeyHex ||
    typeof proof.tick !== "number" ||
    !proof.signedAt
  ) {
    return {
      ok: false,
      code: "MALFORMED_PROOF",
      message: "Malformed proof payload",
    };
  }

  if (
    challenge.cce_ver !== CCE_VERSION ||
    challenge.cce_intent !== challenge.action
  ) {
    return {
      ok: false,
      code: "CHALLENGE_MISMATCH",
      message: "Challenge does not satisfy required CCE invariants",
    };
  }

  // Strong challenge binding: the signed challenge must be byte-for-byte identical.
  const proofChallengeCanonical = canonicalizeCcePayload(proof.challenge);
  const expectedChallengeCanonical = canonicalizeCcePayload(challenge);
  if (proofChallengeCanonical !== expectedChallengeCanonical) {
    return {
      ok: false,
      code: "CHALLENGE_MISMATCH",
      message: "Proof challenge does not match issued challenge",
    };
  }

  if (challenge.sub && proof.challenge.sub !== challenge.sub) {
    return {
      ok: false,
      code: "SUBJECT_MISMATCH",
      message: "Proof subject does not match challenge subject",
    };
  }

  if (proof.sig.kid && proof.sig.kid !== challenge.cce_kid) {
    return {
      ok: false,
      code: "KID_MISMATCH",
      message: "Proof signer key id does not match challenge key id",
    };
  }

  const trustedKey = options.trustedSubjectPublicKeyHex;
  if (options.requireTrustedSubjectKey && !trustedKey) {
    return {
      ok: false,
      code: "MISSING_TRUSTED_SUBJECT_KEY",
      message: "Trusted subject key is required but not provided",
    };
  }

  const verifyKey = trustedKey ?? proof.sig.publicKeyHex;
  const signPayload = serializeProofPayload(
    proof.challenge,
    proof.tick,
    proof.signedAt,
  );
  const signatureValid = await verifyEd25519(
    signPayload,
    proof.sig.sigHex,
    verifyKey,
  );
  if (!signatureValid) {
    return {
      ok: false,
      code: "INVALID_SIGNATURE",
      message: "Proof signature verification failed",
    };
  }

  const driftMs = challenge.window.maxDriftMs ?? 1000;
  if (
    proof.tick < challenge.window.tickStart - driftMs ||
    proof.tick > challenge.window.tickEnd + driftMs
  ) {
    return {
      ok: false,
      code: "OUTSIDE_WINDOW",
      message: "Proof tick is outside challenge TPS window",
    };
  }

  const nowTick = options.currentTickMs ?? getCurrentTick();
  if (nowTick < challenge.window.tickStart - driftMs) {
    return {
      ok: false,
      code: "CHALLENGE_NOT_YET_VALID",
      message: "Challenge TPS window has not started yet",
    };
  }
  if (nowTick > challenge.window.tickEnd + driftMs) {
    return {
      ok: false,
      code: "CHALLENGE_EXPIRED",
      message: "Challenge TPS window has expired",
    };
  }

  return { ok: true, proofHash: hashCceProof(proof) };
}

/**
 * Options for issuing a CCE capsule.
 */
export interface IssueCceCapsuleOptions {
  /** The verified proof */
  proof: TickAuthProof;
  /** The CCE challenge that was answered */
  challenge: CceChallenge;
  /** TickAuth issuer identity (for signing) */
  issuerIdentity: TickAuthIdentity;
  /** Capsule TTL in seconds (default: 60) */
  ttlSeconds?: number;
  /** Usage mode (default: SINGLE_USE) */
  mode?: "SINGLE_USE" | "SESSION";
  /** Override scope */
  scope?: string[];
  /** Override constraints */
  constraints?: CceCapsuleConstraints;
  /** Override policy hash */
  policyHash?: string;
  /** Trusted subject key from registry, if available */
  trustedSubjectPublicKeyHex?: string;
  /** If true and no trustedSubjectPublicKeyHex is provided, fail issuance */
  requireTrustedSubjectKey?: boolean;
  /**
   * Current tick override (ms) for challenge expiry checks.
   */
  currentTickMs?: number;
  /**
   * Skip proof verification when you already validated it externally.
   * Default: false (safe).
   */
  skipProofVerification?: boolean;
}

/**
 * Issue a CCE capsule after successful proof verification.
 *
 * This is the core TickAuth authority operation:
 * 1. Validates that the challenge was properly answered
 * 2. Builds capsule claims bound to intent, audience, subject, and time
 * 3. Signs the claims with the TickAuth issuer key
 * 4. Returns a content-addressed capsule
 */
export async function issueCceCapsule(
  options: IssueCceCapsuleOptions,
): Promise<CceCapsuleClaims> {
  const { proof, challenge, issuerIdentity } = options;
  if (challenge.cce_ver !== CCE_VERSION) {
    throw new Error(
      `issueCceCapsule: unsupported challenge version ${challenge.cce_ver}`,
    );
  }

  let proofHash: string | undefined;
  if (!options.skipProofVerification) {
    const proofResult = await verifyCceProofForChallenge(proof, challenge, {
      trustedSubjectPublicKeyHex: options.trustedSubjectPublicKeyHex,
      requireTrustedSubjectKey: options.requireTrustedSubjectKey,
      currentTickMs: options.currentTickMs,
    });
    if (!proofResult.ok) {
      throw new Error(
        `issueCceCapsule: proof validation failed (${proofResult.code})`,
      );
    }
    proofHash = proofResult.proofHash;
  } else {
    proofHash = hashCceProof(proof);
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const ttl = options.ttlSeconds ?? 60;
  if (!Number.isFinite(ttl) || ttl <= 0) {
    throw new Error("issueCceCapsule: ttlSeconds must be a positive number");
  }

  // Build claims without capsule_id and signature (computed after)
  const baseClaims: Omit<CceCapsuleClaims, "capsule_id" | "issuer_sig"> = {
    ver: CCE_VERSION,
    sub: challenge.sub ?? proof.challenge.sub ?? proof.sig.publicKeyHex,
    kid: challenge.cce_kid,
    intent: challenge.cce_intent,
    aud: challenge.cce_audience,
    tps_from: challenge.window.tickStart,
    tps_to: challenge.window.tickEnd,
    capsule_nonce: challenge.nonce,
    challenge_id: challenge.id,
    ...(proofHash ? { proof_hash: proofHash } : {}),
    ...((options.policyHash ?? challenge.cce_policy_hash)
      ? { policy_hash: options.policyHash ?? challenge.cce_policy_hash }
      : {}),
    iat: nowSeconds,
    exp: nowSeconds + ttl,
    mode: options.mode ?? "SINGLE_USE",
    ...((options.scope ?? challenge.cce_scope)
      ? { scope: options.scope ?? challenge.cce_scope }
      : {}),
    ...((options.constraints ?? challenge.cce_constraints)
      ? {
          constraints: options.constraints ?? challenge.cce_constraints,
        }
      : {}),
  };

  // Compute content-addressed ID
  const capsule_id = computeCceCapsuleId(baseClaims);

  // Build claims with ID for signing
  const claimsForSigning: Omit<CceCapsuleClaims, "issuer_sig"> = {
    capsule_id,
    ...baseClaims,
  };

  // Sign with TickAuth issuer key
  const signPayload = buildCapsuleSignPayload(claimsForSigning);
  const sigValue = await signEd25519(signPayload, issuerIdentity.privateKeyHex);

  const issuer_sig: CceSignature = {
    alg: "EdDSA",
    kid: issuerIdentity.kid ?? "tickauth-issuer",
    value: sigValue,
  };

  return {
    ...claimsForSigning,
    issuer_sig,
  };
}

/**
 * Verify a CCE capsule's issuer signature.
 * Used by AXIS to confirm TickAuth authorized this capsule.
 */
export async function verifyCceCapsuleSignature(
  capsule: CceCapsuleClaims,
  issuerPublicKeyHex: string,
): Promise<boolean> {
  const { issuer_sig, ...rest } = capsule;
  const signPayload = buildCapsuleSignPayload(
    rest as Omit<CceCapsuleClaims, "issuer_sig">,
  );
  return verifyEd25519(signPayload, issuer_sig.value, issuerPublicKeyHex);
}

/**
 * Verify capsule content integrity (ID matches content hash).
 */
export function verifyCceCapsuleIntegrity(capsule: CceCapsuleClaims): boolean {
  const { capsule_id, issuer_sig, ...rest } = capsule;
  const expected = computeCceCapsuleId(rest);
  return capsule_id === expected;
}
