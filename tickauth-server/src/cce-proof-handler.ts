import {
  issueCceCapsule,
  verifyCceProofForChallenge,
  type CceCapsuleClaims,
  type CceCapsuleConstraints,
  type TickAuthIdentity,
  type TickAuthProof,
} from "@nextera.one/tickauth-sdk";

import type { CceChallengeStore } from "./cce-challenge-store";
import type { CapsuleStore } from "./store";

export interface CreateCceProofHandlerOptions {
  challengeStore: CceChallengeStore;
  /**
   * Optional capsule store for persisting issued capsules.
   */
  capsuleStore?: CapsuleStore;
  /**
   * TickAuth issuer identity used to sign CCE capsules.
   */
  issuerIdentity: TickAuthIdentity;
  /**
   * Resolve trusted client public keys from your identity registry.
   * When configured, CCE proof verification requires the resolved key.
   */
  resolveTrustedSubjectKey?: (input: {
    sub?: string;
    kid: string;
  }) => Promise<string | null>;
  defaultTtlSeconds?: number;
  defaultCapsuleMode?: "SINGLE_USE" | "SESSION";
  includeCapsuleInResponse?: boolean;
}

export interface CceProofIssueRequest {
  proof: TickAuthProof;
  challenge_id?: string;
  ttlSeconds?: number;
  mode?: "SINGLE_USE" | "SESSION";
  scope?: string[];
  constraints?: CceCapsuleConstraints;
  policyHash?: string;
}

export interface CceProofHandlerResponse {
  status: number;
  body: {
    ok: boolean;
    capsule_id?: string;
    capsule?: CceCapsuleClaims;
    error?: string;
    message?: string;
  };
}

export function createCceProofHandler(options: CreateCceProofHandlerOptions) {
  const {
    challengeStore,
    capsuleStore,
    issuerIdentity,
    resolveTrustedSubjectKey,
    defaultTtlSeconds = 60,
    defaultCapsuleMode = "SINGLE_USE",
    includeCapsuleInResponse = false,
  } = options;

  return async function cceProofHandler(
    body: unknown,
  ): Promise<CceProofHandlerResponse> {
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

    const input = body as Partial<CceProofIssueRequest>;
    if (!input.proof || typeof input.proof !== "object") {
      return {
        status: 400,
        body: {
          ok: false,
          error: "INVALID_PROOF",
          message: "proof is required",
        },
      };
    }

    const proof = input.proof as TickAuthProof;
    const challengeId = input.challenge_id ?? proof.challenge?.id;
    if (!challengeId) {
      return {
        status: 400,
        body: {
          ok: false,
          error: "CHALLENGE_ID_REQUIRED",
          message: "challenge_id is required",
        },
      };
    }

    const challenge = await challengeStore.get(challengeId);
    if (!challenge) {
      return {
        status: 404,
        body: {
          ok: false,
          error: "CHALLENGE_NOT_FOUND",
          message: `Challenge ${challengeId} not found`,
        },
      };
    }

    const lifecycle = await challengeStore.getLifecycle(challengeId);
    if (lifecycle?.status === "consumed") {
      return {
        status: 409,
        body: {
          ok: false,
          error: "CHALLENGE_CONSUMED",
          message: "Challenge has already been consumed",
        },
      };
    }
    if (lifecycle?.status === "expired") {
      return {
        status: 401,
        body: {
          ok: false,
          error: "CHALLENGE_EXPIRED",
          message: "Challenge has expired",
        },
      };
    }

    let trustedSubjectPublicKeyHex: string | undefined;
    if (resolveTrustedSubjectKey) {
      trustedSubjectPublicKeyHex =
        (await resolveTrustedSubjectKey({
          sub: challenge.sub,
          kid: challenge.cce_kid,
        })) ?? undefined;
      if (!trustedSubjectPublicKeyHex) {
        return {
          status: 403,
          body: {
            ok: false,
            error: "UNKNOWN_SUBJECT_KEY",
            message: `No trusted key found for kid=${challenge.cce_kid}`,
          },
        };
      }
    }

    const proofResult = await verifyCceProofForChallenge(proof, challenge, {
      trustedSubjectPublicKeyHex,
      requireTrustedSubjectKey: Boolean(resolveTrustedSubjectKey),
    });
    if (!proofResult.ok) {
      const status =
        proofResult.code === "INVALID_SIGNATURE"
          ? 401
          : proofResult.code === "CHALLENGE_EXPIRED" ||
              proofResult.code === "OUTSIDE_WINDOW"
            ? 401
            : 400;
      return {
        status,
        body: {
          ok: false,
          error: proofResult.code ?? "INVALID_PROOF",
          message: proofResult.message,
        },
      };
    }

    const consumed = await challengeStore.consume(challengeId);
    if (!consumed) {
      return {
        status: 409,
        body: {
          ok: false,
          error: "CHALLENGE_CONSUMED",
          message: "Challenge was already consumed",
        },
      };
    }

    const capsule = await issueCceCapsule({
      proof,
      challenge,
      issuerIdentity,
      ttlSeconds: input.ttlSeconds ?? defaultTtlSeconds,
      mode: input.mode ?? defaultCapsuleMode,
      scope: input.scope,
      constraints: input.constraints,
      policyHash: input.policyHash,
      trustedSubjectPublicKeyHex,
      requireTrustedSubjectKey: Boolean(resolveTrustedSubjectKey),
      skipProofVerification: true,
    });

    if (capsuleStore) {
      const nowIso = new Date(capsule.iat * 1000).toISOString();
      await capsuleStore.put({
        capsule_id: capsule.capsule_id,
        capsule_version: 1,
        capsule_type: "tickauth.authorization",
        subject: capsule.sub,
        intent: { action: capsule.intent },
        tick_index: challenge.window.tickStart,
        nonce: capsule.capsule_nonce,
        challenge_id: capsule.challenge_id,
        mode: challenge.mode,
        verification: { status: "approved" },
        issued_at: nowIso,
        valid_from: nowIso,
        valid_until: new Date(capsule.exp * 1000).toISOString(),
        scope: capsule.scope,
        single_use: capsule.mode === "SINGLE_USE",
      });
    }

    return {
      status: 200,
      body: {
        ok: true,
        capsule_id: capsule.capsule_id,
        ...(includeCapsuleInResponse ? { capsule } : {}),
      },
    };
  };
}
