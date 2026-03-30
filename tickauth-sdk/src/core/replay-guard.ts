/**
 * TickAuth SDK - Replay Guard
 * ---------------------------
 * Prevents proof reuse through nonce tracking.
 */

interface NonceEntry {
  nonce: string;
  expiresAt: number;
}

/**
 * In-memory replay guard for preventing proof reuse.
 * In production, use a distributed store (Redis, etc.).
 */
export class ReplayGuard {
  private seen: Map<string, NonceEntry> = new Map();
  private ttlMs: number;

  /**
   * Create a replay guard.
   * @param ttlMs - Time-to-live for nonce entries (default: 5 minutes)
   */
  constructor(ttlMs: number = 5 * 60 * 1000) {
    this.ttlMs = ttlMs;
  }

  /**
   * Check if a nonce has been seen before.
   * If not seen, marks it as used.
   *
   * @param nonce - The nonce to check
   * @returns true if this is a new (valid) nonce, false if replay detected
   */
  check(nonce: string): boolean {
    this.cleanup();

    if (this.seen.has(nonce)) {
      return false; // Replay detected
    }

    this.seen.set(nonce, {
      nonce,
      expiresAt: Date.now() + this.ttlMs,
    });

    return true;
  }

  /**
   * Check if a nonce has been seen (without marking as used).
   */
  hasSeen(nonce: string): boolean {
    return this.seen.has(nonce);
  }

  /**
   * Clear expired entries.
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.seen) {
      if (entry.expiresAt < now) {
        this.seen.delete(key);
      }
    }
  }

  /**
   * Remove a specific nonce from tracking.
   * Use with caution — only invalidate nonces you explicitly intend to allow again.
   */
  remove(nonce: string): void {
    this.seen.delete(nonce);
  }

  /**
   * Clear all entries.
   */
  clear(): void {
    this.seen.clear();
  }

  /**
   * Get the number of tracked nonces.
   */
  get size(): number {
    return this.seen.size;
  }
}

// Default shared instance
let defaultGuard: ReplayGuard | null = null;

/**
 * Get or create the default replay guard instance.
 */
export function getDefaultReplayGuard(): ReplayGuard {
  if (!defaultGuard) {
    defaultGuard = new ReplayGuard();
  }
  return defaultGuard;
}

/**
 * Async replay guard interface for distributed deployments.
 *
 * Implement this interface backed by Redis (or any atomic store) for
 * multi-instance production environments where the in-memory ReplayGuard
 * would be bypassed by sibling processes.
 *
 * @example Redis implementation sketch
 * ```ts
 * class RedisReplayGuard implements ReplayGuardStore {
 *   async checkAndMark(nonce: string, ttlMs = 300_000): Promise<boolean> {
 *     const key = `tickauth:nonce:${nonce}`;
 *     const set = await redis.set(key, '1', 'NX', 'PX', ttlMs);
 *     return set === 'OK'; // null means already existed
 *   }
 *   async remove(nonce: string): Promise<void> {
 *     await redis.del(`tickauth:nonce:${nonce}`);
 *   }
 * }
 * ```
 */
export interface ReplayGuardStore {
  /**
   * Atomically check and mark a nonce.
   * Returns true if the nonce is new (not seen before), false if replay detected.
   * The implementation MUST be atomic to prevent race conditions.
   *
   * @param nonce  - The unique nonce or replay key to check.
   * @param ttlMs  - How long to remember the nonce (ms). Default: 5 minutes.
   */
  checkAndMark(nonce: string, ttlMs?: number): Promise<boolean>;

  /**
   * Remove a stored nonce.
   * Use to explicitly invalidate a nonce (e.g. on challenge cancellation).
   */
  remove(nonce: string): Promise<void>;
}

/**
 * In-memory async adapter implementing ReplayGuardStore.
 * Wraps the synchronous ReplayGuard for async-compatible code paths.
 *
 * NOT suitable for multi-instance deployments — use a Redis adapter in production.
 */
export class InMemoryAsyncReplayGuard implements ReplayGuardStore {
  private readonly guard: ReplayGuard;

  constructor(ttlMs?: number) {
    this.guard = new ReplayGuard(ttlMs);
  }

  async checkAndMark(nonce: string): Promise<boolean> {
    return this.guard.check(nonce);
  }

  async remove(nonce: string): Promise<void> {
    this.guard.remove(nonce);
  }
}
