# @nextera.one/tickauth-cli

Command-line interface for the **TickAuth Temporal Authorization Protocol**.

## Installation

```bash
npm install -g @nextera.one/tickauth-cli
```

## Commands

### Initialize Identity

```bash
tickauth init [--out <path>] [--kid <kid>]
```

Creates an Ed25519 keypair for signing TickAuth proofs.

### Create Challenge

```bash
tickauth challenge -a <action> [-m <mode>] [-w <ms>] [-r <rp>] [-s <sub>] [-o <path>]
```

Creates a temporal authorization challenge.

| Option         | Description          | Default    |
| -------------- | -------------------- | ---------- |
| `-a, --action` | Action to authorize  | _required_ |
| `-m, --mode`   | TickAuth mode        | PRESENCE   |
| `-w, --window` | Window duration (ms) | 30000      |
| `-r, --rp`     | Relying party ID     | -          |
| `-s, --sub`    | Subject ID           | -          |
| `-o, --out`    | Output file          | stdout     |

### Sign Challenge

```bash
tickauth sign -c <challenge.json> [-i <identity.json>] [-o <path>]
```

Signs a challenge to create a proof.

### Verify Proof

```bash
tickauth verify -p <proof.json> [--pubkey <hex>] [--skip-replay]
```

Verifies a TickAuth proof.

## Example Flow

```bash
# 1. Initialize identity
tickauth init

# 2. Create a challenge
tickauth challenge -a "funds.transfer" -m PRESENCE -o challenge.json

# 3. Sign the challenge
tickauth sign -c challenge.json -o proof.json

# 4. Verify the proof
tickauth verify -p proof.json
```

## TickAuth Modes

- `PASSKEY` - Browser passkey mode
- `ATTESTED` - Device attestation mode
- `PRESENCE` - Continuous presence mode
- `OFFLINE` - Offline/airgap mode
- `AGENT` - Service/agent mode

## License

Apache-2.0
