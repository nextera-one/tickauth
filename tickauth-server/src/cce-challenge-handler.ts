import {
  createCceChallenge,
  signCceChallenge,
  type CceCapsuleConstraints,
  type CceChallenge,
  type CceSignedChallenge,
  type TickAuthIdentity,
  type TickAuthMode,
} from "@nextera.one/tickauth-sdk";

import type { CceChallengeStore } from "./cce-challenge-store";

export interface CreateCceChallengeHandlerOptions {
  store: CceChallengeStore;
  /**
   * If provided, issued challenges are signed and returned in signed form.
   */
  issuerIdentity?: TickAuthIdentity;
  /**
   * Default challenge mode when caller omits mode.
   */
  defaultMode?: TickAuthMode;
  /**
   * Default challenge validity window in milliseconds.
   */
  defaultWindowMs?: number;
}

export interface CceChallengeCreateRequest {
  sub: string;
  kid: string;
  intent: string;
  audience: string;
  mode?: TickAuthMode;
  windowMs?: number;
  rp?: string;
  scope?: string[];
  constraints?: CceCapsuleConstraints;
  policyHash?: string;
  tickIndex?: number;
  tickTps?: string;
  tickProfile?: string;
}

export interface CceChallengeHandlerResponse {
  status: number;
  body: {
    ok: boolean;
    challenge_id?: string;
    challenge?: CceChallenge;
    signed_challenge?: CceSignedChallenge;
    error?: string;
    message?: string;
  };
}

export function createCceChallengeHandler(
  options: CreateCceChallengeHandlerOptions,
) {
  const {
    store,
    issuerIdentity,
    defaultMode = "PRESENCE",
    defaultWindowMs = 30_000,
  } = options;

  return async function cceChallengeHandler(
    body: unknown,
  ): Promise<CceChallengeHandlerResponse> {
    if (!body || typeof body !== "object") {
      return {
        status: 400,
        body: {
          ok: false,
          error: "INVALID_REQUEST",
          message: "Request body must be a JSON object",
        },
      };
    }

    const input = body as Partial<CceChallengeCreateRequest>;
    if (
      !input.sub?.trim() ||
      !input.kid?.trim() ||
      !input.intent?.trim() ||
      !input.audience?.trim()
    ) {
      return {
        status: 400,
        body: {
          ok: false,
          error: "INVALID_REQUEST",
          message: "sub, kid, intent, and audience are required",
        },
      };
    }

    const challenge = createCceChallenge({
      sub: input.sub,
      kid: input.kid,
      intent: input.intent,
      audience: input.audience,
      mode: input.mode ?? defaultMode,
      windowMs: input.windowMs ?? defaultWindowMs,
      rp: input.rp,
      scope: input.scope,
      constraints: input.constraints,
      policyHash: input.policyHash,
      tickIndex: input.tickIndex,
      tickTps: input.tickTps,
      tickProfile: input.tickProfile,
    });

    await store.put(challenge);

    if (!issuerIdentity) {
      return {
        status: 201,
        body: { ok: true, challenge_id: challenge.id, challenge },
      };
    }

    const signedChallenge = await signCceChallenge(challenge, issuerIdentity);
    return {
      status: 201,
      body: {
        ok: true,
        challenge_id: challenge.id,
        challenge,
        signed_challenge: signedChallenge,
      },
    };
  };
}
