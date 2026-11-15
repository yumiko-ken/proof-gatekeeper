// Vercel serverless adapter for the Proof Gatekeeper agent.
// Registered endpoint path: /agent (rewrite in vercel.json maps /agent here).
import { handlePost, log } from "../lib/core.mjs";

export const config = { api: { bodyParser: false } };

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  if (req.method === "GET") {
    res.status(200).json({ ok: true, protocolVersion: "v1", service: "proof-gatekeeper" });
    return;
  }
  if (req.method !== "POST") { res.status(405).end(); return; }
  try {
    const raw = await readRaw(req);
    const out = await handlePost(raw, req.headers["x-agent-games-signature"]);
    if (out.sig) res.setHeader("x-agent-games-signature", out.sig);
    res.status(out.status).setHeader("content-type", "application/json").send(out.body);
  } catch (e) {
    log({ ev: "adapter_error", err: String(e).slice(0, 160) });
    res.status(500).json({ error: "internal" });
  }
}
