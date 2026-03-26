/**
 * TickAuth SDK - Challenge Creation
 * ----------------------------------
 * Create temporal authorization challenges.
 */

import { ulid } from 'ulid';
import type { TickAuthChallenge, CreateChallengeOptions, TickWindow } from './types';
import { generateNonce } from './crypto';

/**
 * Get current tick (milliseconds since epoch).
 * In production, this could be replaced with a CTS tick source.
 */
export function getCurrentTick(): number {
  return Date.now();
}

/**
 * Create a temporal authorization challenge.
 *
 * @param options - Challenge options
 * @returns A new TickAuth challenge
 *
 * @example
 * ```ts
 * const challenge = createChallenge({
 *   action: 'funds.transfer',
 *   mode: 'PRESENCE',
 *   windowMs: 30000,
 * });
 * ```
 */

export function createChallenge(options: CreateChallengeOptions): TickAuthChallenge {
  const now = getCurrentTick();
  const windowMs = options.windowMs ?? 30000; // Default 30 seconds

  // Support both ms-based and TPS-based windows
  const window: TickWindow = {
    tickStart: options.tickIndex ?? now,
    tickEnd: options.tickIndex ? options.tickIndex : now + windowMs,
    maxDriftMs: 1000, // 1 second drift tolerance
  };
  if (options.tickTps) {
    window.tpsStart = options.tickTps;
    window.tpsEnd = options.tickTps;
  }

  const challenge: TickAuthChallenge = {
    v: 1,
    id: ulid(),
    action: options.action,
    mode: options.mode,
    window,
    nonce: generateNonce(32),
    iat: new Date(now).toISOString(),
  };

  if (options.rp) challenge.rp = options.rp;
  if (options.sub) challenge.sub = options.sub;
  if (options.ctx) challenge.ctx = options.ctx;
  if (options.tickIndex) challenge.tickIndex = options.tickIndex;
  if (options.tickTps) challenge.tickTps = options.tickTps;
  if (options.tickProfile) challenge.tickProfile = options.tickProfile;
  if (options.driftPolicy) challenge.driftPolicy = options.driftPolicy;

  return challenge;
}

/**
 * Serialize a challenge for signing.
 * Creates a canonical representation of the challenge.
 */
export function serializeChallenge(challenge: TickAuthChallenge): Uint8Array {
  // Canonical JSON representation (deep sorted keys)
  function deepSort(obj: any): any {
    if (Array.isArray(obj)) {
      return obj.map(deepSort);
    } else if (obj && typeof obj === 'object') {
      return Object.keys(obj)
        .sort()
        .reduce((acc, key) => {
          acc[key] = deepSort(obj[key]);
          return acc;
        }, {} as any);
    }
    return obj;
  }
  const canonical = JSON.stringify(deepSort(challenge));
  return new TextEncoder().encode(canonical);
}
