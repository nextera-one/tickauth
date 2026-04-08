import { describe, expect, it } from "vitest";

import {
  bytesToHex,
  createCceChallenge,
  generateEd25519Keypair,
  hashCceProof,
  issueCceCapsule,
  signCceChallenge,
  signChallenge,
  verifyCceCapsuleIntegrity,
  verifyCceCapsuleSignature,
  verifyCceChallengeSignature,
  verifyCceProofForChallenge,
  type TickAuthIdentity,
} from "./index";

async function createIdentity(kid: string): Promise<TickAuthIdentity> {
  const { privateKey, publicKey } = await generateEd25519Keypair();
  return {
    alg: "ed25519",
    kid,
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
    createdAt: new Date().toISOString(),
  };
}

describe("CCE capsule issuance", () => {
  it("binds signed proof, challenge, subject key, and capsule signature", async () => {
    const issuer = await createIdentity("tickauth-issuer");
    const client = await createIdentity("client-key-1");
    const challenge = createCceChallenge({
      sub: "user:alice",
      kid: client.kid!,
      intent: "axis.echo",
      audience: "axis:test",
      mode: "PRESENCE",
      windowMs: 30_000,
      policyHash: "policy_b3_test",
    });

    const signedChallenge = await signCceChallenge(challenge, issuer);
    await expect(
      verifyCceChallengeSignature(signedChallenge, issuer.publicKeyHex),
    ).resolves.toBe(true);

    const proof = await signChallenge(challenge, client);
    await expect(
      verifyCceProofForChallenge(proof, challenge, {
        trustedSubjectPublicKeyHex: client.publicKeyHex,
        requireTrustedSubjectKey: true,
      }),
    ).resolves.toMatchObject({ ok: true, proofHash: hashCceProof(proof) });

    const capsule = await issueCceCapsule({
      proof,
      challenge,
      issuerIdentity: issuer,
      trustedSubjectPublicKeyHex: client.publicKeyHex,
      requireTrustedSubjectKey: true,
      ttlSeconds: 60,
    });

    expect(capsule).toMatchObject({
      sub: "user:alice",
      kid: client.kid,
      intent: "axis.echo",
      aud: "axis:test",
      challenge_id: challenge.id,
      proof_hash: hashCceProof(proof),
      policy_hash: "policy_b3_test",
      mode: "SINGLE_USE",
    });
    expect(verifyCceCapsuleIntegrity(capsule)).toBe(true);
    await expect(
      verifyCceCapsuleSignature(capsule, issuer.publicKeyHex),
    ).resolves.toBe(true);
  });

  it("rejects proof reuse against a different CCE challenge", async () => {
    const issuer = await createIdentity("tickauth-issuer");
    const client = await createIdentity("client-key-1");
    const challenge = createCceChallenge({
      sub: "user:alice",
      kid: client.kid!,
      intent: "axis.echo",
      audience: "axis:test",
      mode: "PRESENCE",
      windowMs: 30_000,
    });
    const otherChallenge = createCceChallenge({
      sub: "user:alice",
      kid: client.kid!,
      intent: "axis.echo",
      audience: "axis:other",
      mode: "PRESENCE",
      windowMs: 30_000,
    });

    const proof = await signChallenge(challenge, client);

    await expect(
      verifyCceProofForChallenge(proof, otherChallenge, {
        trustedSubjectPublicKeyHex: client.publicKeyHex,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: "CHALLENGE_MISMATCH",
    });

    await expect(
      issueCceCapsule({
        proof,
        challenge: otherChallenge,
        issuerIdentity: issuer,
        trustedSubjectPublicKeyHex: client.publicKeyHex,
      }),
    ).rejects.toThrow("proof validation failed (CHALLENGE_MISMATCH)");
  });
});
