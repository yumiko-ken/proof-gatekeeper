// Proof Gatekeeper core logic (shared by the Vercel serverless adapter).
// Deterministic APPROVE/REJECT + local Groth16 proof (snarkjs) + Kurier
// submission to zkVerify mainnet. Fail closed: errors degrade to REJECT,
// never to an unproven APPROVE. Secrets come from env vars only.
import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import * as snarkjs from "snarkjs";

const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";

export const CFG = {
  secret: process.env.AGENT_GAMES_HMAC_SECRET || "",
  kurierKey: process.env.KURIER_API_KEY || "",
  kurierUrl: process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1",
  vkHash: process.env.GATEKEEPER_VK_HASH || "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  circuitsDir: process.env.CIRCUITS_DIR || path.join(process.cwd(), "circuits"),
  dataDir: process.env.DATA_DIR || path.join(os.tmpdir(), "gatekeeper-data"),
  kurierBudgetMs: Number(process.env.KURIER_POLL_BUDGET_MS || 12000),
};
const WASM = path.join(CFG.circuitsDir, "gatekeeper.wasm");
const ZKEY = path.join(CFG.circuitsDir, "gatekeeper_final.zkey");
const SEEN_PATH = path.join(CFG.dataDir, "seen.json");

export function log(obj) { console.log(JSON.stringify({ t: new Date().toISOString(), ...obj })); }

export function signBody(secret, raw) {
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}
function verifySig(secret, raw, header) {
  if (!secret || !header) return false;
  let v = String(header).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice(7).trim();
  let cand = null;
  if (/^[0-9a-fA-F]{64}$/.test(v)) cand = Buffer.from(v, "hex");
  else { try { const b = Buffer.from(v, "base64"); if (b.length === 32) cand = b; } catch {} }
  if (!cand) return false;
  const exp = crypto.createHmac("sha256", secret).update(raw).digest();
  return cand.length === exp.length && crypto.timingSafeEqual(cand, exp);
}

function parseUint(v) {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}
function toField(v) {
  let n;
  if (typeof v === "bigint") n = v;
  else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else { const d = crypto.createHash("sha256").update(s).digest(); n = BigInt("0x" + d.toString("hex")); }
  }
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}
const normHex = (v) => String(v ?? "").trim().toLowerCase();

class SeenStore {
  constructor(file) {
    this.file = file; this.seen = new Set(); this.responses = new Map();
    try {
      const d = JSON.parse(fs.readFileSync(file, "utf8"));
      for (const tx of d.proofTx || []) this.seen.add(normHex(tx));
      for (const [k, val] of Object.entries(d.responses || {})) this.responses.set(k, val);
    } catch {}
  }
  persist() {
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const tmp = this.file + ".tmp";
      fs.writeFileSync(tmp, JSON.stringify({ proofTx: [...this.seen], responses: Object.fromEntries(this.responses) }));
      fs.renameSync(tmp, this.file);
    } catch (e) { console.error("[seen] persist failed:", e.message); }
  }
  has(tx) { return this.seen.has(normHex(tx)); }
  record(tx) { const k = normHex(tx); if (k && !this.seen.has(k)) { this.seen.add(k); this.persist(); } }
  getResp(id) { return this.responses.get(id) || null; }
  putResp(id, body) { this.responses.set(id, body); this.persist(); }
}
const store = new SeenStore(SEEN_PATH);

function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum), publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount), maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block), currentBlock = parseUint(input.current_block);
  if ([minimum, publicBalance, amount, maxTransfer, expiryBlock, currentBlock].some((x) => x === null)) return null;
  for (const k of ["registered_vk", "proof_vk", "recipient", "condition_recipient", "proof_tx"])
    if (typeof input[k] !== "string" || !input[k]) return null;
  return { registeredVk: input.registered_vk, proofVk: input.proof_vk, minimum, publicBalance,
           expiryBlock, currentBlock, recipient: input.recipient, conditionRecipient: input.condition_recipient,
           amount, maxTransfer, proofTx: input.proof_tx };
}
function evaluate(p) {
  if (normHex(p.proofVk) !== normHex(p.registeredVk)) return { decision: "REJECT", reason: "VK_SUBSTITUTION", provable: true };
  if (store.has(p.proofTx)) return { decision: "REJECT", reason: "PROOF_REUSED", provable: false };
  if (p.publicBalance < p.minimum) return { decision: "REJECT", reason: "THRESHOLD_MISMATCH", provable: true };
  if (p.currentBlock >= p.expiryBlock) return { decision: "REJECT", reason: "EXPIRED_CONDITION", provable: true };
  if (normHex(p.recipient) !== normHex(p.conditionRecipient)) return { decision: "REJECT", reason: "RECIPIENT_MISMATCH", provable: true };
  if (p.amount > p.maxTransfer) return { decision: "REJECT", reason: "AMOUNT_OVERFLOW", provable: true };
  return { decision: "APPROVE", reason: "VALID_CONDITION", provable: true };
}
function circuitInputs(task, p, decision) {
  const salt = BigInt("0x" + crypto.createHmac("sha256", CFG.secret).update("gatekeeper-salt:" + task.task_id).digest("hex")) % BN128_PRIME;
  return {
    taskId: toField(task.task_id),
    registeredVkHash: toField(p.registeredVk), proofVkHash: toField(p.proofVk),
    minimum: p.minimum.toString(10), publicBalance: p.publicBalance.toString(10),
    expiryBlock: p.expiryBlock.toString(10), currentBlock: p.currentBlock.toString(10),
    recipient: toField(p.recipient), conditionRecipient: toField(p.conditionRecipient),
    amount: p.amount.toString(10), maxTransfer: p.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0", salt: salt.toString(10),
  };
}

async function kurierSubmit(proof, publicSignals, budgetMs) {
  if (!CFG.kurierKey) return null;
  const t0 = Date.now();
  try {
    const r = await fetch(`${CFG.kurierUrl}/submit-proof/${CFG.kurierKey}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ proofType: "groth16", vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: CFG.vkHash } }),
    });
    const job = await r.json().catch(() => ({}));
    if (!r.ok || !job.jobId) { log({ ev: "kurier_submit_failed", status: r.status }); return null; }
    let status = job.status || "Queued", txHash = job.txHash || null;
    while (Date.now() - t0 < budgetMs) {
      if (txHash) break;
      await new Promise((res) => setTimeout(res, 2000));
      const sr = await fetch(`${CFG.kurierUrl}/job-status/${CFG.kurierKey}/${job.jobId}`);
      const sj = await sr.json().catch(() => ({}));
      status = sj.status || status; txHash = sj.txHash || txHash;
      if (["Failed", "Finalized"].includes(status)) break;
    }
    log({ ev: "kurier", jobId: job.jobId, status, txHash, ms: Date.now() - t0 });
    return { jobId: job.jobId, status, txHash };
  } catch (e) { log({ ev: "kurier_error", err: String(e).slice(0, 160) }); return null; }
}

function signed(status, obj) {
  const body = typeof obj === "string" ? obj : JSON.stringify(obj);
  return { status, body, sig: signBody(CFG.secret, body) };
}

export async function handlePost(raw, sigHeader) {
  const t0 = Date.now();
  if (!CFG.secret) return { status: 500, body: JSON.stringify({ error: "server_misconfigured" }), sig: null };
  if (!verifySig(CFG.secret, raw, sigHeader)) return { status: 401, body: JSON.stringify({ error: "invalid_signature" }), sig: null };
  let env;
  try { env = JSON.parse(raw.toString("utf8")); }
  catch { return signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" }); }
  if (env.type === PREFLIGHT_TYPE) { log({ ev: "preflight" }); return signed(200, { ok: true, protocolVersion: "v1" }); }
  if (env.type !== TASK_TYPE) return signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });

  const taskId = env.task_id;
  if (taskId && store.getResp(taskId)) { log({ ev: "redelivery", taskId }); return signed(200, store.getResp(taskId)); }
  const parsed = parseInput(env.input);
  if (!parsed || !taskId) { log({ ev: "invalid_task", taskId }); return signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" }); }

  const ev = evaluate(parsed);
  const resp = { decision: ev.decision, reason_code: ev.reason };
  if (ev.provable) {
    try {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInputs(env, parsed, ev.decision), WASM, ZKEY);
      resp.proof = proof; resp.public_signals = publicSignals;
      const k = await kurierSubmit(proof, publicSignals, CFG.kurierBudgetMs);
      resp.proof_tx = k?.txHash || parsed.proofTx;
    } catch (e) {
      log({ ev: "prove_failed", taskId, err: String(e).slice(0, 160) });
      return signed(200, { decision: "REJECT", reason_code: ev.decision === "APPROVE" ? "INVALID_TASK" : ev.reason, proof_tx: parsed.proofTx });
    }
  } else {
    resp.proof_tx = parsed.proofTx;
  }
  const out = signed(200, resp);
  store.record(parsed.proofTx);
  store.putResp(taskId, out.body);
  log({ ev: "task", taskId, mode: env.mode || null, decision: ev.decision, reason: ev.reason, ms: Date.now() - t0 });
  return out;
}
