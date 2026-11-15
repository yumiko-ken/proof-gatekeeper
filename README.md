# Proof Gatekeeper Agent

An autonomous agent for the **Proof Gatekeeper** event of the
[Agent Games by zkVerify](https://agentgames.zkverify.io) (Season 01).

The platform sends signed payment-approval tasks to the agent's public HTTPS
endpoint. For each task the agent evaluates the payment condition, produces a
real **Groth16 proof** (BN128, snarkjs) of its evaluation against the official
gatekeeper circuit, submits the proof for on-chain verification via
[Kurier](https://kurier.xyz), and returns a signed APPROVE / REJECT decision —
all inside the 60-second task deadline.

## How it decides

The circuit itself defines correctness: it asserts that the decision equals
the AND of all condition checks, so a dishonest decision is mathematically
unprovable. The agent mirrors those semantics exactly:

- verification-key substitution (registered VK vs proof VK)
- proof reuse across tasks (local seen-set of proof transactions)
- threshold mismatch (balance below the required minimum)
- expired condition (current block at or past the expiry block)
- recipient mismatch (transfer recipient vs condition recipient)
- amount overflow (amount above the maximum transfer)

## Architecture

- `api/agent.mjs` — serverless adapter (Vercel), routes `/agent` requests
- `lib/core.mjs` — protocol core: HMAC request/response signing, evaluation,
  witness generation, Groth16 proving, Kurier submission with idempotent
  redelivery handling
- `circuits/` — the official `gatekeeper.wasm` + `gatekeeper_final.zkey`
- Decisions are deterministic; the proof salt is derived per task, and every
  response is signed with the agent's HMAC secret

## Running

Deployed on Vercel (Fluid Compute, 60s function budget). Required env vars:

- `AGENT_GAMES_HMAC_SECRET` — the agent secret issued by the Agent Games
  dashboard
- `KURIER_API_KEY` — Kurier mainnet API key for proof submission

Built and operated by Koda for Yumiko (`yumiko` on the Agent Games
leaderboard).
