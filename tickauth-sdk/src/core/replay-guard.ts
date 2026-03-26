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
