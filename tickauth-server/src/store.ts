/**
 * TickAuth Server — Capsule Store
 * --------------------------------
 * Persistent capsule storage interface and default in-memory implementation.
 *
 * Capsules store the immutable evidence artifacts produced after every
 * TickAuth authorization decision. Replace InMemoryCapsuleStore with a
 * real database adapter for production deployments.
 */
import type { CapsuleStatus, TickAuthCapsule } from '@nextera.one/tickauth-sdk';

/**
 * Query filters for listing capsules.
 */
export interface CapsuleQuery {
  subject?: string;
  status?: CapsuleStatus;
  challenge_id?: string;
  issuer?: string;
  /** Filter by current lifecycle status (active / consumed / revoked) */
  lifecycleStatus?: 'active' | 'consumed' | 'revoked';
  /** ISO date — return capsules issued after this date */
  after?: string;
  /** ISO date — return capsules issued before this date */
  before?: string;
  limit?: number;
  offset?: number;
}

/**
 * Lifecycle state of a capsule tracked outside its immutable content.
 * Capsule content is always immutable (content-addressed); revocation
 * and consumption are recorded separately by the store.
 */
export interface CapsuleLifecycle {
  /** Current lifecycle status */
  status: 'active' | 'consumed' | 'revoked';
  /** Reason for revocation (if applicable) */
  reason?: string;
  /** ISO timestamp of the last status change */
  updatedAt: string;
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
  /**
   * Revoke a capsule post-issuance.
   * Returns true if successfully revoked, false if not found or already inactive.
   */
  revoke(capsule_id: string, reason?: string): Promise<boolean>;
  /**
   * Mark a capsule as consumed (single-use enforcement).
   * Returns true if successfully consumed, false if not found or already inactive.
   */
  consume(capsule_id: string): Promise<boolean>;
  /**
   * Get the current lifecycle status of a capsule.
   * Returns null if the capsule does not exist.
   */
  getLifecycle(capsule_id: string): Promise<CapsuleLifecycle | null>;
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
  /** Tracks lifecycle overrides separately so capsule content stays immutable */
  private readonly lifecycle = new Map<string, { status: 'revoked' | 'consumed'; reason?: string; updatedAt: string }>();

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

    if (filters.lifecycleStatus === 'active') {
      results = results.filter(c => !this.lifecycle.has(c.capsule_id));
    } else if (filters.lifecycleStatus === 'consumed') {
      results = results.filter(c => this.lifecycle.get(c.capsule_id)?.status === 'consumed');
    } else if (filters.lifecycleStatus === 'revoked') {
      results = results.filter(c => this.lifecycle.get(c.capsule_id)?.status === 'revoked');
    }

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

  async revoke(capsule_id: string, reason?: string): Promise<boolean> {
    if (!this.store.has(capsule_id)) return false;
    if (this.lifecycle.has(capsule_id)) return false; // already revoked or consumed
    this.lifecycle.set(capsule_id, { status: 'revoked', reason, updatedAt: new Date().toISOString() });
    return true;
  }

  async consume(capsule_id: string): Promise<boolean> {
    if (!this.store.has(capsule_id)) return false;
    if (this.lifecycle.has(capsule_id)) return false; // already consumed or revoked
    this.lifecycle.set(capsule_id, { status: 'consumed', updatedAt: new Date().toISOString() });
    return true;
  }

  async getLifecycle(capsule_id: string): Promise<CapsuleLifecycle | null> {
    const capsule = this.store.get(capsule_id);
    if (!capsule) return null;
    const override = this.lifecycle.get(capsule_id);
    if (override) {
      return { status: override.status, reason: override.reason, updatedAt: override.updatedAt };
    }
    return { status: 'active', updatedAt: capsule.issued_at };
  }
}
