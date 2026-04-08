import type { CceChallenge } from "@nextera.one/tickauth-sdk";

export type CceChallengeLifecycleStatus = "active" | "consumed" | "expired";

export interface CceChallengeLifecycle {
  status: CceChallengeLifecycleStatus;
  updatedAt: string;
}

/**
 * Challenge store for one-time CCE challenges.
 * Challenge state is mutable even though challenge payloads are immutable.
 */
export interface CceChallengeStore {
  put(challenge: CceChallenge): Promise<void>;
  get(challengeId: string): Promise<CceChallenge | null>;
  consume(challengeId: string): Promise<boolean>;
  getLifecycle(challengeId: string): Promise<CceChallengeLifecycle | null>;
}

/**
 * In-memory challenge store for development and single-process deployments.
 * Replace with Redis/Postgres implementation in production.
 */
export class InMemoryCceChallengeStore implements CceChallengeStore {
  private readonly challenges = new Map<string, CceChallenge>();
  private readonly consumed = new Map<string, string>();
  private readonly maxSize: number;

  constructor(options?: { maxSize?: number }) {
    this.maxSize = options?.maxSize ?? 100_000;
  }

  async put(challenge: CceChallenge): Promise<void> {
    if (this.challenges.has(challenge.id)) return;

    if (this.challenges.size >= this.maxSize) {
      const oldest = this.challenges.keys().next().value;
      if (oldest !== undefined) {
        this.challenges.delete(oldest);
        this.consumed.delete(oldest);
      }
    }

    this.challenges.set(challenge.id, challenge);
  }

  async get(challengeId: string): Promise<CceChallenge | null> {
    return this.challenges.get(challengeId) ?? null;
  }

  async consume(challengeId: string): Promise<boolean> {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) return false;
    if (this.consumed.has(challengeId)) return false;

    const now = Date.now();
    const drift = challenge.window.maxDriftMs ?? 1000;
    if (now > challenge.window.tickEnd + drift) return false;

    this.consumed.set(challengeId, new Date(now).toISOString());
    return true;
  }

  async getLifecycle(challengeId: string): Promise<CceChallengeLifecycle | null> {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) return null;

    const consumedAt = this.consumed.get(challengeId);
    if (consumedAt) {
      return { status: "consumed", updatedAt: consumedAt };
    }

    const now = Date.now();
    const drift = challenge.window.maxDriftMs ?? 1000;
    if (now > challenge.window.tickEnd + drift) {
      return { status: "expired", updatedAt: new Date(now).toISOString() };
    }

    return { status: "active", updatedAt: challenge.iat };
  }
}
