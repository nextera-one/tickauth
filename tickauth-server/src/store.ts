/**
 * TickAuth Server — Capsule Store
 * --------------------------------
 * Persistent capsule storage interface and default in-memory implementation.
 *
 * Capsules store the immutable evidence artifacts produced after every
 * TickAuth authorization decision. Replace InMemoryCapsuleStore with a
 * real database adapter for production deployments.
 */

import type { TickAuthCapsule, CapsuleStatus } from '@nextera.one/tickauth-sdk';

/**
 * Query filters for listing capsules.
 */
export interface CapsuleQuery {
  subject?: string;
  status?: CapsuleStatus;
  challenge_id?: string;
  issuer?: string;
  /** ISO date — return capsules issued after this date */
  after?: string;
  /** ISO date — return capsules issued before this date */
  before?: string;
  limit?: number;
  offset?: number;
}

/**
 * Capsule store interface.
 * Implement this interface to plug in any storage backend (Postgres, Redis, etc.).
 */
export interface CapsuleStore {
  /** Persist a capsule (idempotent — storing same capsule_id twice is a no-op) */
  put(capsule: TickAuthCapsule): Promise<void>;
  /** Retrieve a capsule by its content-addressed ID */
  get(capsule_id: string): Promise<TickAuthCapsule | null>;
  /** Query capsules with optional filters */
  query(filters?: CapsuleQuery): Promise<TickAuthCapsule[]>;
  /** Check if a capsule exists */
  has(capsule_id: string): Promise<boolean>;
}

/**
 * Minimal in-memory capsule store.
 *
 * Suitable for development, testing, and single-instance deployments.
 * All data is lost on process restart — use an external store for production.
 *
 * @example
 * ```ts
 * const store = new InMemoryCapsuleStore({ maxSize: 50_000 });
 * await store.put(capsule);
 * const c = await store.get('cps_b3_...');
 * ```
 */
export class InMemoryCapsuleStore implements CapsuleStore {
  private readonly store = new Map<string, TickAuthCapsule>();
  private readonly maxSize: number;

  constructor(options?: { maxSize?: number }) {
    this.maxSize = options?.maxSize ?? 100_000;
  }

  async put(capsule: TickAuthCapsule): Promise<void> {
    if (this.store.has(capsule.capsule_id)) return; // idempotent
    if (this.store.size >= this.maxSize) {
      // Evict the oldest entry (first inserted key)
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) this.store.delete(oldest);
    }
    this.store.set(capsule.capsule_id, capsule);
  }

  async get(capsule_id: string): Promise<TickAuthCapsule | null> {
    return this.store.get(capsule_id) ?? null;
  }

  async has(capsule_id: string): Promise<boolean> {
    return this.store.has(capsule_id);
  }

  async query(filters: CapsuleQuery = {}): Promise<TickAuthCapsule[]> {
    let results = [...this.store.values()];

    if (filters.subject)      results = results.filter(c => c.subject === filters.subject);
    if (filters.status)       results = results.filter(c => c.verification.status === filters.status);
    if (filters.challenge_id) results = results.filter(c => c.challenge_id === filters.challenge_id);
    if (filters.issuer)       results = results.filter(c => c.issuer === filters.issuer);
    if (filters.after)        results = results.filter(c => c.issued_at >= filters.after!);
    if (filters.before)       results = results.filter(c => c.issued_at <= filters.before!);

    // Newest first
    results.sort((a, b) => b.issued_at.localeCompare(a.issued_at));

    const offset = filters.offset ?? 0;
    const limit = filters.limit ?? 100;
    return results.slice(offset, offset + limit);
  }

  /** Current count of stored capsules */
  get size(): number {
    return this.store.size;
  }
}
