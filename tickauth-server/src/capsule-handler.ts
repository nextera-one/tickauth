/**
 * TickAuth Server — Capsule Handler
 * -----------------------------------
 * Framework-agnostic handler for GET /capsules/:id
 *
 * Returns a stored Capsule by its content-addressed ID.
 *
 * @example Express
 * ```ts
 * import { createCapsuleHandler } from '@nextera.one/tickauth-server';
 *
 * const capsuleHandler = createCapsuleHandler({ store });
 *
 * app.get('/capsules/:id', async (req, res) => {
 *   const { status, body } = await capsuleHandler(req.params.id);
 *   res.status(status).json(body);
 * });
 * ```
 */
import { verifyCapsuleIntegrity } from "@nextera.one/tickauth-sdk";

import type { CapsuleStore } from "./store";

export interface CapsuleHandlerOptions {
  store: CapsuleStore;
  /**
   * Whether to verify capsule integrity on retrieval.
   * Default: true — validates content hash matches capsule_id.
   */
  verifyIntegrity?: boolean;
}

export interface CapsuleHandlerResponse {
  status: number;
  body: unknown;
}

export function createCapsuleHandler(options: CapsuleHandlerOptions) {
  const { store, verifyIntegrity = true } = options;

  return async function capsuleHandler(
    capsuleId: string,
  ): Promise<CapsuleHandlerResponse> {
    if (!capsuleId || !capsuleId.startsWith("cps_b3_")) {
      return {
        status: 400,
        body: {
          error: "INVALID_CAPSULE_ID",
          message: 'capsule_id must start with "cps_b3_"',
        },
      };
    }

    const capsule = await store.get(capsuleId);
    if (!capsule) {
      return {
        status: 404,
        body: { error: "NOT_FOUND", message: `Capsule ${capsuleId} not found` },
      };
    }

    if (verifyIntegrity && !verifyCapsuleIntegrity(capsule)) {
      return {
        status: 500,
        body: {
          error: "INTEGRITY_FAILURE",
          message: "Capsule content hash mismatch — store may be corrupted",
        },
      };
    }

    const lifecycle = await store.getLifecycle(capsuleId);

    return { status: 200, body: { ...capsule, lifecycle } };
  };
}
