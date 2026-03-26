/**
 * TickAuth SDK - Proof Creation
 * -----------------------------
 * Sign challenges to create authorization proofs.
 */

import type { TickAuthChallenge, TickAuthProof, TickAuthIdentity } from './types';
import { signEd25519 } from './crypto';
import { serializeChallenge, getCurrentTick } from './challenge';

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
  const tick = getCurrentTick();
  const signedAt = new Date(tick).toISOString();

  // Create the message to sign: challenge + tick + signedAt
  const message = new TextEncoder().encode(
    JSON.stringify({
      challenge: serializeChallenge(challenge),
      tick,
      signedAt,
    }),
  );

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
  options?: { kid?: string; interactionType?: 'touch' | 'pin' | 'biometric' },
): TickAuthProof {
  const proof: TickAuthProof = {
    v: 1,
    challenge,
    tick,
    signedAt: new Date(tick).toISOString(),
    sig: {
      alg: 'ed25519',
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
