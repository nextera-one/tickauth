# @nextera.one/tickauth-sdk

TypeScript/JavaScript SDK for the **TickAuth Temporal Authorization Protocol**.

## Installation

```bash
npm install @nextera.one/tickauth-sdk
```

## Quick Start

```typescript
import {
  createChallenge,
  signChallenge,
  verifyProof,
  generateEd25519Keypair,
} from '@nextera.one/tickauth-sdk';

// 1. Generate an identity (one-time setup)
const { privateKey, publicKey } = await generateEd25519Keypair();
const identity = {
  alg: 'ed25519',
  privateKeyHex: Buffer.from(privateKey).toString('hex'),
  publicKeyHex: Buffer.from(publicKey).toString('hex'),
  createdAt: new Date().toISOString(),
};

// 2. Create a temporal challenge
const challenge = createChallenge({
  action: 'funds.transfer',
  mode: 'PRESENCE',
  windowMs: 30000, // 30 second window
});

// 3. Sign the challenge to create a proof
const proof = await signChallenge(challenge, identity);

// 4. Verify the proof
const result = await verifyProof(proof);

if (result.ok) {
  console.log('Authorized:', result.clearance);
} else {
  console.error('Denied:', result.error, result.message);
}
```

## TickAuth Modes

| Mode       | Description                           |
| ---------- | ------------------------------------- |
| `PASSKEY`  | Browser passkey mode (WebAuthn-like)  |
| `ATTESTED` | Device attestation mode               |
| `PRESENCE` | Continuous/step-up presence mode      |
| `OFFLINE`  | Offline/airgap mode                   |
| `AGENT`    | Service/agent mode (non-human actors) |

## API Reference

### Challenge Creation

```typescript
createChallenge(options: CreateChallengeOptions): TickAuthChallenge
```

### Proof Signing

```typescript
signChallenge(challenge: TickAuthChallenge, identity: TickAuthIdentity): Promise<TickAuthProof>
```

### Verification

```typescript
verifyProof(proof: TickAuthProof, options?: VerifyOptions): Promise<VerifyResult>
```

## Security Guarantees

- **Freshness** — authority cannot be reused
- **Replay resistance** — proofs collapse after use
- **Temporal integrity** — authority cannot be deferred
- **Deterministic audit** — every action is time-bound

## License

Apache-2.0
