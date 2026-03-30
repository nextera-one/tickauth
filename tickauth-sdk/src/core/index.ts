/**
 * TickAuth SDK - Core Module Exports
 * -----------------------------------
 */

// Types
export * from "./types";

// Crypto utilities
export {
  generateEd25519Keypair,
  signEd25519,
  verifyEd25519,
  generateNonce,
  bytesToHex,
  hexToBytes,
} from "./crypto";

// Challenge creation
export {
  createChallenge,
  serializeChallenge,
  serializeProofPayload,
  getCurrentTick,
} from "./challenge";

// Proof creation
export { signChallenge, createProofFromSignature } from "./proof";

// Verification
export { verifyProof, isProofInWindow, type VerifyOptions } from "./verify";

// Replay guard
export {
  ReplayGuard,
  getDefaultReplayGuard,
  InMemoryAsyncReplayGuard,
  type ReplayGuardStore,
} from "./replay-guard";

// Capsule
export {
  createCapsule,
  verifyCapsuleIntegrity,
  type CreateCapsuleOptions,
} from "./capsule";
