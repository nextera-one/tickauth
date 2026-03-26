/**
 * TickAuth SDK - Cryptographic Utilities
 * --------------------------------------
 * Ed25519 signing and verification using @noble/ed25519.
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Configure ed25519 to use sha512 (for sync operations)
// @ts-expect-error - sha512Sync may not be in types but is used internally
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

/**
 * Generate an Ed25519 keypair.
 */
export async function generateEd25519Keypair(): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  // Use randomSecretKey or fallback to crypto.getRandomValues
  const privateKey = ed.utils.randomSecretKey
    ? ed.utils.randomSecretKey()
    : crypto.getRandomValues(new Uint8Array(32));
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

/**
 * Sign a message with an Ed25519 private key.
 */
export async function signEd25519(
  message: Uint8Array,
  privateKeyHex: string,
): Promise<string> {
  const privateKey = hexToBytes(privateKeyHex);
  const signature = await ed.signAsync(message, privateKey);
  return bytesToHex(signature);
}

/**
 * Verify an Ed25519 signature.
 */
export async function verifyEd25519(
  message: Uint8Array,
  signatureHex: string,
  publicKeyHex: string,
): Promise<boolean> {
  try {
    const signature = hexToBytes(signatureHex);
    const publicKey = hexToBytes(publicKeyHex);
    return await ed.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Generate a cryptographically secure random nonce.
 */
export function generateNonce(bytes: number = 32): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return bytesToHex(array);
}

/**
 * Convert bytes to hex string.
 */
export { bytesToHex, hexToBytes };
