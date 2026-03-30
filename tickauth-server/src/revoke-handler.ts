/**
 * TickAuth Server — Revoke & Consume Handlers
 * ---------------------------------------------
 * Framework-agnostic handlers for capsule lifecycle management.
 *
 * POST /capsules/:id/revoke  — explicitly revoke a capsule post-issuance.
 * POST /capsules/:id/consume — mark a single-use capsule as consumed.
 *
 * These are separate from the capsule's cryptographic content (which is
 * immutable and content-addressed). Revocation and consumption are tracked
 * as lifecycle state alongside the capsule in the store.
 *
 * @example Express
 * ```ts
 * import { createRevokeHandler, createConsumeHandler } from '@nextera.one/tickauth-server';
 *
 * const revokeHandler  = createRevokeHandler({ store });
 * const consumeHandler = createConsumeHandler({ store });
 *
 * app.post('/capsules/:id/revoke',  async (req, res) => {
 *   const { status, body } = await revokeHandler(req.params.id, req.body?.reason);
 *   res.status(status).json(body);
 * });
 *
 * app.post('/capsules/:id/consume', async (req, res) => {
 *   const { status, body } = await consumeHandler(req.params.id);
 *   res.status(status).json(body);
 * });
 * ```
 */
import type { CapsuleStore } from "./store";

export interface RevokeHandlerOptions {
  store: CapsuleStore;
}

export interface RevokeHandlerResponse {
  status: number;
  body: unknown;
}

/**
 * Create a reusable capsule revocation handler.
 *
 * Revocation is used when a capsule should be invalidated before its
 * natural expiry — e.g. user logs out, device is revoked, or suspicious
 * activity is detected. Revoked capsules remain in the store for audit
 * purposes but are marked inactive.
 */
export function createRevokeHandler(options: RevokeHandlerOptions) {
  const { store } = options;

  return async function revokeHandler(
    capsuleId: string,
    reason?: string,
  ): Promise<RevokeHandlerResponse> {
    if (!capsuleId || !capsuleId.startsWith("cps_b3_")) {
      return {
        status: 400,
        body: {
          error: "INVALID_CAPSULE_ID",
          message: 'capsule_id must start with "cps_b3_"',
        },
      };
    }

    const exists = await store.has(capsuleId);
    if (!exists) {
      return {
        status: 404,
        body: { error: "NOT_FOUND", message: `Capsule ${capsuleId} not found` },
      };
    }

    const revoked = await store.revoke(capsuleId, reason);
    if (!revoked) {
      return {
        status: 409,
        body: {
          error: "ALREADY_INACTIVE",
          message: "Capsule is already revoked or consumed",
        },
      };
    }

    return {
      status: 200,
      body: { ok: true, capsule_id: capsuleId, lifecycle_status: "revoked" },
    };
  };
}

/**
 * Create a reusable capsule consume handler.
 *
 * Consumption is used for single-use capsules (single_use: true) — once
 * consumed the capsule cannot be used again. Typical use: a login capsule
 * that issues exactly one session, or a one-time device registration approval.
 *
 * The caller is responsible for issuing the downstream credential (session,
 * device trust link, etc.) atomically before or after calling this handler.
 */
export function createConsumeHandler(options: RevokeHandlerOptions) {
  const { store } = options;

  return async function consumeHandler(
    capsuleId: string,
  ): Promise<RevokeHandlerResponse> {
    if (!capsuleId || !capsuleId.startsWith("cps_b3_")) {
      return {
        status: 400,
        body: {
          error: "INVALID_CAPSULE_ID",
          message: 'capsule_id must start with "cps_b3_"',
        },
      };
    }

    const exists = await store.has(capsuleId);
    if (!exists) {
      return {
        status: 404,
        body: { error: "NOT_FOUND", message: `Capsule ${capsuleId} not found` },
      };
    }

    const consumed = await store.consume(capsuleId);
    if (!consumed) {
      return {
        status: 409,
        body: {
          error: "ALREADY_CONSUMED",
          message:
            "Capsule is already consumed or revoked and cannot be used again",
        },
      };
    }

    return {
      status: 200,
      body: { ok: true, capsule_id: capsuleId, lifecycle_status: "consumed" },
    };
  };
}
