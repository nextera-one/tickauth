# @nextera.one/tickauth-server

Server runtime for the TickAuth Temporal Authorization Protocol.

Provides a **CapsuleStore**, framework-agnostic HTTP handlers, and the foundation for building TickAuth-enabled authorization servers.

## Install

```bash
npm install @nextera.one/tickauth-server @nextera.one/tickauth-sdk
```

## Quickstart

```ts
import {
  InMemoryCapsuleStore,
  createVerifyHandler,
  createCapsuleHandler,
} from '@nextera.one/tickauth-server';
import express from 'express';

const store = new InMemoryCapsuleStore();

// POST /verify — accept and verify a TickAuth proof
const verifyHandler = createVerifyHandler({
  publicKeyHex: process.env.TICKAUTH_TRUSTED_KEY!,
  store,
});

// GET /capsules/:id — retrieve a stored capsule
const capsuleHandler = createCapsuleHandler({ store });

const app = express();
app.use(express.json());

app.post('/verify', async (req, res) => {
  const { status, body } = await verifyHandler(req.body);
  res.status(status).json(body);
});

app.get('/capsules/:id', async (req, res) => {
  const { status, body } = await capsuleHandler(req.params['id']);
  res.status(status).json(body);
});

app.listen(3000);
```

## Verify Response

```json
{
  "ok": true,
  "capsule_id": "cps_b3_a3f1...",
  "capsule_status": "approved"
}
```

Full capsule can be retrieved via `GET /capsules/:capsule_id`.

## Capsule Response

```json
{
  "capsule_id": "cps_b3_a3f1...",
  "capsule_version": 1,
  "capsule_type": "tickauth.authorization",
  "subject": "user:alice",
  "intent": { "action": "payments:transfer" },
  "tick_index": 1718000000000,
  "nonce": "...",
  "challenge_id": "...",
  "mode": "PASSKEY",
  "verification": {
    "status": "approved"
  },
  "issued_at": "2024-06-10T00:00:00.000Z"
}
```

## Custom Store

Implement `CapsuleStore` to use any backend:

```ts
import type { CapsuleStore } from '@nextera.one/tickauth-server';
import type { TickAuthCapsule } from '@nextera.one/tickauth-sdk';

class PostgresCapsuleStore implements CapsuleStore {
  async put(capsule: TickAuthCapsule) { /* INSERT ... ON CONFLICT DO NOTHING */ }
  async get(capsule_id: string) { /* SELECT ... WHERE capsule_id = $1 */ }
  async has(capsule_id: string) { /* SELECT EXISTS ... */ }
  async query(filters) { /* SELECT ... WHERE ... */ }
}
```

## Part of the TickAuth Ecosystem

| Package | Purpose |
|---|---|
| `@nextera.one/tickauth-sdk` | Core protocol (challenges, proofs, capsules) |
| `@nextera.one/tickauth-server` | Server runtime (this package) |
| `@nextera.one/tickauth-cli` | CLI tools for development |

More at [tickauth.org](https://tickauth.org)
