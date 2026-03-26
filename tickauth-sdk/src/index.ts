/**
 * TickAuth SDK
 * ------------
 * TypeScript/JavaScript SDK for the TickAuth Temporal Authorization Protocol.
 *
 * @example
 * ```ts
 * import { createChallenge, signChallenge, verifyProof } from '@nextera.one/tickauth-sdk';
 *
 * // Create a challenge
 * const challenge = createChallenge({
 *   action: 'funds.transfer',
 *   mode: 'PRESENCE',
 *   windowMs: 30000,
 * });
 *
 * // Sign the challenge
 * const proof = await signChallenge(challenge, identity);
 *
 * // Verify the proof
 * const result = await verifyProof(proof);
 * ```
 */

export * from './core';
