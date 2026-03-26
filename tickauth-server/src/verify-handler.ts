/**
 * TickAuth Server — Verify Handler
 * ---------------------------------
 * Framework-agnostic request handler for POST /verify.
 *
 * Accepts a TickAuth proof JSON body, runs verifyProof(), stores the
 * resulting Capsule, and returns a structured response.
 *
 * Integrate with any HTTP framework by using createVerifyHandler():
 *
 * @example Express
 * ```ts
 * import express from 'express';
 * import { createVerifyHandler } from '@nextera.one/tickauth-server';
 *
 * const app = express();
 * const handler = createVerifyHandler({ publicKeyHex: trustedKey, store });
 *
 * app.post('/verify', express.json(), async (req, res) => {
 *   const { status, body } = await handler(req.body);
 *   res.status(status).json(body);
 * });
 * ```
 */

import { verifyProof, type TickAuthProof, type VerifyOptions } from '@nextera.one/tickauth-sdk';
import type { CapsuleStore } from './store';

export interface VerifyHandlerOptions extends VerifyOptions {
  /** Capsule store to persist the result */
  store?: CapsuleStore;
  /**
   * Whether to include the full capsule in the response body.
   * Default: false — only capsule_id and status are returned.
   */
  includeCapsuleInResponse?: boolean;
}

export interface VerifyHandlerResponse {
  /** HTTP status code to return */
  status: number;
  /** Response body */
  body: {
    ok: boolean;
    capsule_id?: string;
    capsule_status?: string;
    error?: string;
    message?: string;
    capsule?: unknown;
  };
}

/**
 * Create a reusable verify handler.
 * The handler is pure — it accepts a parsed JSON body and returns { status, body }.
 */
export function createVerifyHandler(options: VerifyHandlerOptions = {}) {
  const { store, includeCapsuleInResponse = false, ...verifyOptions } = options;

  return async function verifyHandler(body: unknown): Promise<VerifyHandlerResponse> {
    // Validate minimal proof shape before passing to SDK
    if (
      !body ||
      typeof body !== 'object' ||
      !('v' in body) ||
      !('challenge' in body) ||
      !('sig' in body)
    ) {
      return {
        status: 400,
        body: { ok: false, error: 'INVALID_PROOF', message: 'Request body is not a valid TickAuth proof' },
      };
    }

    const proof = body as TickAuthProof;
    const result = await verifyProof(proof, verifyOptions);

    // Store the capsule (fire-and-forget is intentional — don't block the response)
    if (store && result.capsule) {
      store.put(result.capsule).catch(() => {
        // Store failures are non-fatal but should be monitored
      });
    }

    if (!result.ok) {
      return {
        status: 401,
        body: {
          ok: false,
          capsule_id: result.capsule_id,
          capsule_status: result.capsule?.verification.status,
          error: result.error,
          message: result.message,
          ...(includeCapsuleInResponse && result.capsule ? { capsule: result.capsule } : {}),
        },
      };
    }

    return {
      status: 200,
      body: {
        ok: true,
        capsule_id: result.capsule_id,
        capsule_status: result.capsule?.verification.status,
        ...(includeCapsuleInResponse && result.capsule ? { capsule: result.capsule } : {}),
      },
    };
  };
}
