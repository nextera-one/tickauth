/**
 * TickAuth SDK v1.0 Types
 * -----------------------
 * Core types for the TickAuth Temporal Authorization Protocol.
 */

/**
 * TickAuth verification modes as defined in the protocol spec.
 */
export type TickAuthMode =
  | "PASSKEY" // Mode A: Browser Passkey Mode (WebAuthn-like)
  | "ATTESTED" // Mode B: Device Attestation Mode
  | "PRESENCE" // Mode C: Continuous/Step-up Presence Mode
  | "OFFLINE" // Mode D: Offline/Airgap Mode
  | "AGENT"; // Mode E: Service/Agent Mode (non-human actors)

export type TickAuthAlg = "ed25519";

/**
 * Tick window defines the temporal authorization bounds.
 */
import type { TPSComponents } from "@nextera.one/tps-standard";

/**
 * Tick window defines the temporal authorization bounds.
 * Supports both ms-based and TPS-based windows for compatibility.
 */
export interface TickWindow {
  /** Earliest valid tick (inclusive, ms or TPS index) */
  tickStart: number;
  /** Latest valid tick (inclusive, ms or TPS index) */
  tickEnd: number;
  /** Maximum allowed clock drift in milliseconds */
  maxDriftMs?: number;
  /** Optional TPS coordinate for start (human readable) */
  tpsStart?: string | TPSComponents;
  /** Optional TPS coordinate for end (human readable) */
  tpsEnd?: string | TPSComponents;
}

/**
 * TickAuth challenge issued by the verifier.
 */
export interface TickAuthChallenge {
  /** Protocol version */
  v: 1;
  /** Unique challenge identifier */
  id: string;
  /** Action being authorized */
  action: string;
  /** Required verification mode */
  mode: TickAuthMode;
  /** Tick window for validity */
  window: TickWindow;
  /** Cryptographic nonce (hex) */
  nonce: string;
  /** Relying party identifier (domain/scope) */
  rp?: string;
  /** Subject identifier */
  sub?: string;
  /** Challenge creation timestamp (ISO) */
  iat: string;
  /** Optional context data */
  ctx?: Record<string, unknown>;
  /**
   * Subject's public key (hex) to bind in the proof.
   * For QR login: the browser's ephemeral public key that the mobile app approves.
   * Ensures the approval is cryptographically bound to one specific device/session key.
   */
  subject_public_key_hex?: string;
  /** Optional TPS tick (canonical, machine index) */
  tickIndex?: number;
  /** Optional TPS tick (human readable) */
  tickTps?: string;
  /** Optional tick profile (e.g. TickAuth-M, TickAuth-H) */
  tickProfile?: string;
  /** Optional drift policy (allowed past/future ticks) */
  driftPolicy?: { past: number; future: number };
}

/**
 * Signature container.
 */
export interface TickAuthSignature {
  /** Signing algorithm */
  alg: TickAuthAlg;
  /** Public key (hex) */
  publicKeyHex: string;
  /** Signature (hex) */
  sigHex: string;
  /** Optional key identifier */
  kid?: string;
}

/**
 * TickAuth proof - a signed challenge.
 */
export interface TickAuthProof {
  /** Protocol version */
  v: 1;
  /** The original challenge */
  challenge: TickAuthChallenge;
  /** Tick at which proof was created (ms or TPS index) */
  tick: number;
  /** Optional TPS tick (canonical, machine index) */
  tickIndex?: number;
  /** Optional TPS tick (human readable) */
  tickTps?: string;
  /** Proof creation timestamp (ISO) */
  signedAt: string;
  /** Cryptographic signature */
  sig: TickAuthSignature;
  /** Optional interaction type for PRESENCE mode */
  interactionType?: "touch" | "pin" | "biometric";
}

/**
 * Short-lived clearance grant after successful verification.
 */
export interface TickAuthClearance {
  /** Whether authorization was granted */
  granted: boolean;
  /** The original challenge id */
  challengeId: string;
  /** Action that was authorized */
  action: string;
  /** Mode that was verified */
  mode: TickAuthMode;
  /** Tick at which clearance was issued */
  tick: number;
  /** Clearance expiration timestamp (ISO) */
  expiresAt: string;
}

/**
 * Capsule verification outcome.
 */
export type CapsuleStatus =
  | "approved"
  | "denied"
  | "expired"
  | "replay_rejected"
  | "consumed" // single-use capsule was consumed after first use
  | "revoked"; // explicitly revoked post-issuance

/**
 * Capsule type — classifies the authorization event that produced the capsule.
 */
export type CapsuleType =
  | "tickauth.authorization" // generic (backward-compatible default)
  | "tickauth.login" // QR / passwordless web login
  | "tickauth.device_registration" // new device or browser trust registration
  | "tickauth.step_up" // step-up for sensitive actions in an active session
  | "tickauth.recovery"; // account or device recovery flow

/**
 * TickAuth Capsule — the canonical evidence artifact produced after verification.
 *
 * A Capsule is the authoritative record of a TickAuth authorization decision.
 * Its ID is content-addressed: capsule_id = "cps_b3_" + blake3(canonical JSON).
 * This makes every Capsule self-verifiable without querying the issuing server.
 */
export interface TickAuthCapsule {
  /** Content-addressed capsule identifier: cps_b3_<blake3hex> */
  capsule_id: string;
  /** Capsule schema version */
  capsule_version: 1;
  /** Capsule type */
  capsule_type: CapsuleType;
  /** Subject performing the action (e.g. "user:alice", "service:billing-api") */
  subject?: string;
  /** Intent being authorized */
  intent: {
    action: string;
    resource?: string;
    [key: string]: unknown;
  };
  /** Canonical tick index (ms since epoch or TPS index) */
  tick_index: number;
  /** Human-readable TPS coordinate (optional) */
  tick_tps?: string;
  /** Declared tick profile (e.g. "TickAuth-M") */
  tick_profile?: string;
  /** Nonce from the challenge */
  nonce: string;
  /** Original challenge ID */
  challenge_id: string;
  /** Verification mode used */
  mode: TickAuthMode;
  /** Verification decision */
  verification: {
    status: CapsuleStatus;
    /** Denial reason if status is not 'approved' */
    reason?: string;
    /** Clock drift applied in ms */
    drift_applied?: number;
  };
  /** Issuer URI (e.g. "tickauth://auth.example") */
  issuer?: string;
  /** ISO timestamp of capsule creation */
  issued_at: string;
  /** ISO timestamp — earliest this capsule is valid (for future-dated issuance) */
  valid_from?: string;
  /** ISO timestamp — this capsule expires at this time */
  valid_until?: string;
  /** Device ID that issued/approved this capsule (e.g. mobile app device) */
  issuer_device_id?: string;
  /** Device ID of the subject being authorized (e.g. browser device) */
  subject_device_id?: string;
  /** Permissions or capabilities granted by this capsule */
  scope?: string[];
  /** If true, this capsule may only be consumed once */
  single_use?: boolean;
  /**
   * Optional parent capsule IDs — for forming authorization chains/graphs.
   * Use for PRESENCE step-up to link back to the originating session capsule.
   */
  parents?: string[];
}

/**
 * Result of proof verification.
 */
export interface VerifyResult {
  /** Whether verification succeeded */
  ok: boolean;
  /** Error code if failed */
  error?:
    | "INVALID_SIGNATURE"
    | "OUTSIDE_WINDOW"
    | "REPLAY_DETECTED"
    | "DRIFT_EXCEEDED"
    | "POLICY_DENIED"
    | "INVALID_PROOF"
    | "MODE_MISMATCH"
    | "ACTION_MISMATCH";
  /** Human-readable error message */
  message?: string;
  /**
   * The Capsule produced by this verification (both on success and failure).
   * Every decision — approved, denied, or replay-rejected — produces a Capsule.
   */
  capsule?: TickAuthCapsule;
  /** Content-addressed capsule ID (shorthand for capsule.capsule_id) */
  capsule_id?: string;
  /**
   * @deprecated Use `capsule` instead. Kept for backward compatibility.
   */
  clearance?: TickAuthClearance;
}

/**
 * Identity keypair for signing.
 */
export interface TickAuthIdentity {
  alg: TickAuthAlg;
  kid?: string;
  privateKeyHex: string;
  publicKeyHex: string;
  createdAt: string;
}

/**
 * Options for creating a challenge.
 */
export interface CreateChallengeOptions {
  /** Action being authorized */
  action: string;
  /** Verification mode */
  mode: TickAuthMode;
  /** Window duration in milliseconds (default: 30000) */
  windowMs?: number;
  /** Optionally use TPS tick (canonical, machine index) */
  tickIndex?: number;
  /** Optionally use TPS tick (human readable) */
  tickTps?: string;
  /** Optionally use tick profile (e.g. TickAuth-M, TickAuth-H) */
  tickProfile?: string;
  /** Optionally set drift policy (allowed past/future ticks) */
  driftPolicy?: { past: number; future: number };
  /** Relying party identifier */
  rp?: string;
  /** Subject identifier */
  sub?: string;
  /** Optional context */
  ctx?: Record<string, unknown>;
  /**
   * Subject's public key to embed in the challenge (e.g. browser key for QR login).
   * Stored as `subject_public_key_hex` on the challenge so the signer explicitly
   * approves that specific key, preventing browser key substitution attacks.
   */
  subjectPublicKeyHex?: string;
}

/**
 * How replay uniqueness is computed for proofs.
 */
export type ReplayScope = "nonce" | "challenge" | "proof";
