import { getCurrentTick, serializeProofPayload } from "./challenge";
import { signEd25519 } from "./crypto";
/**
 * TickAuth SDK - Proof Creation
 * -----------------------------
 * Sign challenges to create authorization proofs.
 */
import type { TickAuthChallenge, TickAuthIdentity, TickAuthProof } from "./types";

/**
 * Sign a challenge to create a proof.
 *
 * @param challenge - The challenge to sign
 * @param identity - The signing identity
 * @returns A signed TickAuth proof
 *
 * @example
 * ```ts
 * const proof = await signChallenge(challenge, identity);
 * ```
 */
export async function signChallenge(
  challenge: TickAuthChallenge,
  identity: TickAuthIdentity,
): Promise<TickAuthProof> {
  if (!challenge.action || !challenge.action.trim()) {
    throw new Error("signChallenge: challenge.action must be non-empty");
  }

  const tick = getCurrentTick();
  const signedAt = new Date(tick).toISOString();

  // Create the canonical message to sign.
  const message = serializeProofPayload(challenge, tick, signedAt);

  const sigHex = await signEd25519(message, identity.privateKeyHex);

  const proof: TickAuthProof = {
    v: 1,
    challenge,
    tick,
    signedAt,
    sig: {
      alg: identity.alg,
      publicKeyHex: identity.publicKeyHex,
      sigHex,
      kid: identity.kid,
    },
  };

  return proof;
}

/**
 * Create a proof from an already-computed signature.
 * Used when signing happens externally (e.g., hardware token).
 */
export function createProofFromSignature(
  challenge: TickAuthChallenge,
  tick: number,
  sigHex: string,
  publicKeyHex: string,
  options?: { kid?: string; interactionType?: "touch" | "pin" | "biometric" },
): TickAuthProof {
  if (!challenge.action || !challenge.action.trim()) {
    throw new Error(
      "createProofFromSignature: challenge.action must be non-empty",
    );
  }

  const proof: TickAuthProof = {
    v: 1,
    challenge,
    tick,
    signedAt: new Date(tick).toISOString(),
    sig: {
      alg: "ed25519",
      publicKeyHex,
      sigHex,
      kid: options?.kid,
    },
  };

  if (options?.interactionType) {
    proof.interactionType = options.interactionType;
  }

  return proof;
}
