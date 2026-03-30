/**
 * @nextera.one/tickauth-server
 * ----------------------------
 * TickAuth server runtime — capsule store, retrieval, and HTTP handlers.
 *
 * Provides:
 * - CapsuleStore interface + InMemoryCapsuleStore
 * - createVerifyHandler() — framework-agnostic POST /verify handler
 * - createCapsuleHandler() — framework-agnostic GET /capsules/:id handler
 *
 * @example
 * ```ts
 * import {
 *   InMemoryCapsuleStore,
 *   createVerifyHandler,
 *   createCapsuleHandler,
 * } from '@nextera.one/tickauth-server';
 *
 * const store = new InMemoryCapsuleStore();
 * const verifyHandler = createVerifyHandler({ publicKeyHex: trustedKey, store });
 * const capsuleHandler = createCapsuleHandler({ store });
 * ```
 */

// Store
export {
  InMemoryCapsuleStore,
  type CapsuleStore,
  type CapsuleQuery,
  type CapsuleLifecycle,
} from "./store";

// Handlers
export {
  createVerifyHandler,
  type VerifyHandlerOptions,
  type VerifyHandlerResponse,
} from "./verify-handler";

export {
  createCapsuleHandler,
  type CapsuleHandlerOptions,
  type CapsuleHandlerResponse,
} from "./capsule-handler";

export {
  createRevokeHandler,
  createConsumeHandler,
  type RevokeHandlerOptions,
  type RevokeHandlerResponse,
} from "./revoke-handler";
