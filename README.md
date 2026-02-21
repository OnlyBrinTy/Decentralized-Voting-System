# Blockchain Voting (demo)

This is a small, educational voting system implemented as an **append-only, in-memory blockchain** with **Proof-of-Work** and **RSA-PSS signatures**.

## How does it work?

1. The **Authority** creates a master RSA keypair.
2. A user runs `/issue_keys`. The Authority returns **two certified public keys** (and their private exponents):
   - a **voter** key where \(n \bmod 100 > 50\)
   - a **participant-registration** key where \(n \bmod 100 < 50\)
3. To **register a candidate**, a user submits a block with `{"nickname": "...", "name": "..."}` and their participant key certificate.
4. To **cast a vote**, a user submits a block with `{"voted_for": "nickname"}` and their voter key certificate.
5. On every submission, the **blockchain** attempts to append the block: it links it (`prev_hash`, index), **mines** it (PoW: hash \(\le\) target), **signs** it (RSA-PSS over the block hash), then **validates the entire chain**.
6. If any validation fails, the attempted append is **rolled back** and the block is rejected.

Validation includes: hash links, sequential indexes, chronological timestamps, PoW target, block signatures, Authority certificates, uniqueness of nicknames, votes must target an existing candidate, correct key type for the block, and no public key reuse (prevents double-voting / duplicate registration).

## Why do we need an Authority?

Without an Authority, the system has no way to prevent “Sybil” abuse: a user could generate unlimited keypairs and vote many times. The Authority acts as a gatekeeper that **certifies** which public keys are allowed on-chain (conceptually tied to a real-world identity or eligibility check done off-chain).

## Why does the Authority issue two keys?

This demo splits actions into two capabilities: **registering a candidate** vs **casting a vote**. The validator enforces that each action uses the correct key type (via \(n \bmod 100\)), so a voting credential can’t be used to register candidates and vice versa.

## Why can’t users make a bunch of their own keys?

They can generate keys locally, but those keys won’t be accepted because the blockchain requires an **Authority certificate** for every public key used in a block. Also, the validator rejects any reuse of the same key, so even a certified key can’t be used twice.

## Run

```bash
python run.py
```

Use `/issue_keys` to get certified keys, then `/add_participant ...` and `/vote ...`.
