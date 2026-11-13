// Raft push relay for external agents (multi-agent, one Cloudflare Worker).
//
// Raft can push an external agent's inbox notices (schema raft-agent-inbox-notice.v1) to an HTTPS
// URL, signed with X-Raft-Signature-256: sha256=<hex HMAC-SHA256(raw body, push secret)>.
// This Worker receives them and forwards the raw JSON to each agent's own webhook with a Bearer key.
//
// Registration (POST /raft/register) is done by the agent itself:
//   - X-Relay-Registration-Key: the relay's registration key. The Worker stores only its SHA-256
//     (REGISTRATION_KEY_SHA256), so the Worker's configuration never reveals the key.
//   - Authorization: Bearer <the agent's own Raft agent credential>. The Worker asks the fixed
//     RAFT_SERVER who it belongs to (must be an agent on RAFT_SERVER_ID), registers the push webhook
//     for that agent itself, and does not keep the credential.
//   - body {webhookUrl, webhookToken}: where to forward and with which Bearer key. The token is kept
//     in KV encrypted (AES-GCM, key derived from MASTER_KEY) and never returned.
// The push secret is never stored or shown to anyone: it is derived as
// HMAC-SHA256(MASTER_KEY, "raft-push:<agentId>:<generation>").
// Retries are Raft's: forwarding failures answer 503. Never 404/410 (three in a row disable push).

const MAX_BODY = 256 * 1024;
const FORWARD_TIMEOUT_MS = 15000;
const DEDUP_TTL_S = 7 * 24 * 3600;
const PREV_GRACE_S = 600;
const enc = new TextEncoder();
const dec = new TextDecoder();

function json(status, obj, extra = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...extra } });
}
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
function hexToBytes(h) {
  if (!/^[0-9a-f]*$/i.test(h) || h.length % 2) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function hmacKey(secret, usage) {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}
export async function deriveSecret(masterKey, agentId, gen) {
  return hex(await crypto.subtle.sign("HMAC", await hmacKey(masterKey, "sign"), enc.encode(`raft-push:${agentId}:${gen}`)));
}
export async function verifySignature(secret, raw, header) {
  if (!secret || !header || !header.startsWith("sha256=")) return false;
  const sig = hexToBytes(header.slice(7).trim());
  if (!sig || sig.length !== 32) return false;
  return crypto.subtle.verify("HMAC", await hmacKey(secret, "verify"), sig, raw);
}
export async function sha256Hex(s) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

// --- encrypted per-agent config in KV ---
async function aesKey(env) {
  const raw = await crypto.subtle.sign("HMAC", await hmacKey(env.MASTER_KEY, "sign"), enc.encode("relay-config-encryption"));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function saveAgent(env, agentId, cfg) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(agentId) }, await aesKey(env), enc.encode(JSON.stringify(cfg)));
  await env.RELAY.put("agent:" + agentId, hex(iv) + ":" + hex(ct));
}
async function loadAgent(env, agentId) {
  const v = await env.RELAY.get("agent:" + agentId);
  if (!v) return null;
  const [iv, ct] = v.split(":");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(iv), additionalData: enc.encode(agentId) }, await aesKey(env), hexToBytes(ct));
  return JSON.parse(dec.decode(pt));
}

async function raftCall(env, token, method, path, body, agentId) {
  const res = await fetch(env.RAFT_SERVER.replace(/\/$/, "") + "/internal/agent-api" + path, {
    method,
    headers: { authorization: "Bearer " + token, ...(agentId ? { "x-agent-id": agentId } : {}), "x-raft-client": "raft-push-relay",
      ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    redirect: "manual",
    signal: AbortSignal.timeout(FORWARD_TIMEOUT_MS),
  });
  let data = null;
  try { data = await res.json(); } catch {}
  if (data && typeof data === "object" && "ok" in data && "data" in data) data = data.data;
  return { status: res.status, data };
}

function configured(env) {
  return env.MASTER_KEY && env.REGISTRATION_KEY_SHA256 && env.RAFT_SERVER_ID && env.RELAY &&
    env.RAFT_SERVER && /^https:\/\//.test(env.RAFT_SERVER);
}

async function register(request, env, base, log) {
  if (!configured(env)) return json(503, { error: "relay_not_configured" }, base);
  const key = request.headers.get("x-relay-registration-key") || "";
  if (!key || !timingSafeEqualHex(await sha256Hex(key), env.REGISTRATION_KEY_SHA256.toLowerCase())) {
    log({ action: "register_refused", reason: "registration_key" });
    return json(401, { error: "bad_registration_key" }, base);
  }
  const auth = request.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) return json(401, { error: "missing_agent_credential" }, base);

  const who = await raftCall(env, token, "GET", "/context");
  const agent = (who.data && who.data.agent) || {}, server = (who.data && who.data.server) || {};
  if (who.status !== 200 || !agent.id || server.id !== env.RAFT_SERVER_ID) {
    log({ action: "register_refused", reason: "identity", raftStatus: who.status });
    return json(403, { error: "not_an_agent_of_this_server" }, base);
  }
  const agentId = agent.id;
  const existing = await loadAgent(env, agentId);
  const pushUrl = new URL(request.url).origin + "/raft/push/" + agentId;

  if (request.method === "DELETE") {
    const del = await raftCall(env, token, "DELETE", "/push-webhook", null, agentId);
    if (del.status >= 300 && del.status !== 404) return json(502, { error: "raft_unregister_failed", raftStatus: del.status }, base);
    await env.RELAY.delete("agent:" + agentId);
    log({ action: "unregistered", agentId });
    return json(200, { ok: true, agentId, unregistered: true }, base);
  }

  let body = {};
  try { body = await request.json(); } catch {}
  const webhookUrl = body.webhookUrl || (existing && existing.webhookUrl);
  const webhookToken = body.webhookToken || (existing && existing.webhookToken);
  if (!webhookUrl || !/^https:\/\//.test(webhookUrl) || !webhookToken) {
    return json(400, { error: "webhookUrl_https_and_webhookToken_required" }, base);
  }
  const rotate = new URL(request.url).searchParams.get("rotate") === "1";
  const cur = existing ? existing.gen : 0;
  const gen = rotate || !existing ? cur + 1 : cur;
  const secret = await deriveSecret(env.MASTER_KEY, agentId, gen);
  const put = await raftCall(env, token, "PUT", "/push-webhook", { url: pushUrl, secret }, agentId);
  if (put.status < 200 || put.status >= 300) {
    log({ action: "register_failed", agentId, raftStatus: put.status });
    return json(502, { error: "raft_register_failed", raftStatus: put.status, raftError: (put.data && (put.data.error || put.data.code)) || null }, base);
  }
  await saveAgent(env, agentId, { name: agent.name || null, webhookUrl, webhookToken, gen,
    prevGen: gen !== cur && cur ? cur : null, prevUntil: gen !== cur && cur ? Date.now() + PREV_GRACE_S * 1000 : 0 });
  const st = await raftCall(env, token, "GET", "/push-webhook", null, agentId);
  const d = st.data || {};
  log({ action: "registered", agentId, name: agent.name || null, generation: gen, enabled: d.enabled ?? null });
  return json(200, { ok: true, agentId, name: agent.name || null, generation: gen, url: d.url ?? pushUrl,
    enabled: d.enabled ?? null, disabledReason: d.disabledReason ?? null, lastError: d.lastError ?? null }, base);
}

async function push(request, env, base, log, agentId) {
  if (!configured(env)) return json(503, { error: "relay_not_configured" }, base);
  const raw = new Uint8Array(await request.arrayBuffer());
  if (raw.length > MAX_BODY) return json(413, { error: "too_large" }, base);
  const cfg = agentId && /^[A-Za-z0-9-]{8,64}$/.test(agentId) ? await loadAgent(env, agentId) : null;
  if (!cfg) return json(401, { error: "unknown_agent" }, base);
  const gens = [cfg.gen];
  if (cfg.prevGen && Date.now() < cfg.prevUntil) gens.push(cfg.prevGen);
  let valid = false;
  for (const g of gens) {
    if (await verifySignature(await deriveSecret(env.MASTER_KEY, agentId, g), raw, request.headers.get("x-raft-signature-256"))) { valid = true; break; }
  }
  if (!valid) return json(401, { error: "bad_signature" }, base);

  let notice;
  try { notice = JSON.parse(dec.decode(raw)); } catch { return json(400, { error: "bad_json" }, base); }
  if (notice.recipientAgentId && notice.recipientAgentId !== agentId) return json(401, { error: "wrong_recipient" }, base);
  const noticeId = notice.noticeId || request.headers.get("x-raft-delivery-id") || "";
  const l = { agentId, noticeId, traceId: request.headers.get("x-raft-trace-id"), targets: Array.isArray(notice.targets) ? notice.targets.length : null };

  // Nothing pending (e.g. Raft's probe while push is off): acknowledge, do not start a paid run.
  if (!Array.isArray(notice.targets) || notice.targets.length === 0) {
    log({ ...l, action: "skip_empty" });
    return json(200, { ok: true, forwarded: false, reason: "no_targets" }, base);
  }
  const dedupKey = noticeId ? `seen:${agentId}:${noticeId}` : null;
  if (dedupKey && (await env.RELAY.get(dedupKey))) {
    log({ ...l, action: "skip_duplicate" });
    return json(200, { ok: true, forwarded: false, reason: "duplicate" }, base);
  }
  let status = 0, err = null;
  try {
    const res = await fetch(cfg.webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer " + cfg.webhookToken,
        "x-raft-delivery-id": noticeId, "x-relay-request-id": base["x-request-id"] },
      body: raw,
      redirect: "manual",
      signal: AbortSignal.timeout(FORWARD_TIMEOUT_MS),
    });
    status = res.status;
  } catch (e) {
    err = String((e && e.name) || e);
  }
  if (status >= 200 && status < 300) {
    if (dedupKey) await env.RELAY.put(dedupKey, "1", { expirationTtl: DEDUP_TTL_S });
    log({ ...l, action: "forwarded", status });
    return json(200, { ok: true, forwarded: true }, base);
  }
  // Target failed: ask Raft to retry. Never pass 401/404/410 back (they count against the registration).
  log({ ...l, action: "forward_failed", status, error: err });
  const retryAfter = status === 401 || status === 403 ? "300" : "30";
  return json(503, { ok: false, error: "forward_failed", targetStatus: status || null }, { ...base, "retry-after": retryAfter });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const requestId = crypto.randomUUID();
    const base = { "x-request-id": requestId };
    const log = o => console.log(JSON.stringify({ requestId, ...o }));
    if (url.pathname === "/raft/register" && (request.method === "POST" || request.method === "DELETE")) {
      return register(request, env, base, log);
    }
    const m = url.pathname.match(/^\/raft\/push\/([^/]+)$/);
    if (m && request.method === "POST") return push(request, env, base, log, m[1]);
    return json(405, { error: "method_or_path_not_allowed" }, base); // never 404/410
  },
};
