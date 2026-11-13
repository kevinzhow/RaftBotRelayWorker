import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import worker, { deriveSecret } from "../src/index.js";

const MASTER = "m".repeat(64);
const REG_KEY = "reg-key-for-tests-0123456789abcdef";
const A = "11111111-2222-3333-4444-555555555555";
const B = "99999999-8888-7777-6666-555555555555";
const ORIGIN = "https://relay.example";

function kv() {
  const m = new Map();
  return { get: async k => m.get(k) ?? null, put: async (k, v) => { m.set(k, v); }, delete: async k => { m.delete(k); }, _m: m };
}
const env0 = () => ({ MASTER_KEY: MASTER, REGISTRATION_KEY_SHA256: createHash("sha256").update(REG_KEY).digest("hex"),
  RAFT_SERVER: "https://raft.example", RAFT_SERVER_ID: "srv-1", RELAY: kv() });

// Raft + webhook fake. Tokens map to agents; webhooks record calls.
function net({ agents = { "tok-a": { id: A, name: "GrokA" }, "tok-b": { id: B, name: "GrokB" } }, serverId = "srv-1", putStatus = 200, hook = [] } = {}) {
  const calls = { raft: [], hook: [] };
  globalThis.fetch = async (url, init) => {
    const ok = (o, st = 200) => new Response(JSON.stringify(o), { status: st, headers: { "content-type": "application/json" } });
    if (url.startsWith("https://raft.example/")) {
      const tok = (init.headers.authorization || "").slice(7);
      calls.raft.push({ url, method: init.method, body: init.body ? JSON.parse(init.body) : null, headers: init.headers });
      const ag = agents[tok];
      if (!ag) return ok({ error: "unauthorized" }, 401);
      if (url.endsWith("/context")) return ok({ agent: ag, server: { id: serverId } });
      if (url.endsWith("/push-webhook") && init.method === "PUT") return ok({}, putStatus);
      if (url.endsWith("/push-webhook") && init.method === "DELETE") return ok({}, 204 === 204 ? 200 : 200);
      if (url.endsWith("/push-webhook")) return ok({ url: "x", enabled: true, lastError: null });
      return ok({}, 500);
    }
    calls.hook.push({ url, init, body: Buffer.from(init.body).toString() });
    const r = hook.shift() ?? 200;
    if (r instanceof Error) throw r;
    return new Response("{}", { status: r });
  };
  return calls;
}

const reg = (token, body, { key = REG_KEY, q = "", method = "POST" } = {}) =>
  new Request(ORIGIN + "/raft/register" + q, { method, body: body ? JSON.stringify(body) : undefined,
    headers: { ...(token ? { authorization: "Bearer " + token } : {}), ...(key ? { "x-relay-registration-key": key } : {}), "content-type": "application/json" } });
const notice = (id, agent = A, targets = [{ target: "#general", flags: ["mention"] }]) =>
  JSON.stringify({ schema: "raft-agent-inbox-notice.v1", noticeId: id, recipientAgentId: agent, occurredAt: "2026-11-13T00:00:00Z", text: "Inbox update", targets });
const sign = (body, secret) => "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
const push = (agent, body, sig) => new Request(ORIGIN + "/raft/push/" + agent, { method: "POST", body, headers: sig ? { "x-raft-signature-256": sig } : {} });

async function registered(env, tok = "tok-a", hookUrl = "https://hook-a.example/x", hookTok = "hook-token-a") {
  const c = net();
  const res = await worker.fetch(reg(tok, { webhookUrl: hookUrl, webhookToken: hookTok }), env);
  assert.equal(res.status, 200);
  return { res: await res.json(), calls: c };
}

test("register: registration key + own credential -> push webhook registered with derived secret", async () => {
  const env = env0();
  const { res, calls } = await registered(env);
  assert.equal(res.agentId, A); assert.equal(res.enabled, true); assert.equal(res.generation, 1);
  const put = calls.raft.find(c => c.method === "PUT");
  assert.deepEqual(put.body, { url: ORIGIN + "/raft/push/" + A, secret: await deriveSecret(MASTER, A, 1) });
  assert.ok(!JSON.stringify(res).includes(put.body.secret));
  // webhook token stored encrypted, not in clear
  const stored = env.RELAY._m.get("agent:" + A);
  assert.ok(stored && !stored.includes("hook-token-a") && !stored.includes("hook-a.example"));
});

test("register: wrong/missing registration key -> 401 and Raft never called", async () => {
  const env = env0(); const c = net();
  assert.equal((await worker.fetch(reg("tok-a", { webhookUrl: "https://h", webhookToken: "t" }, { key: "nope" }), env)).status, 401);
  assert.equal((await worker.fetch(reg("tok-a", { webhookUrl: "https://h", webhookToken: "t" }, { key: null }), env)).status, 401);
  assert.equal(c.raft.length, 0);
});

test("register: bad credential or other server -> 403, nothing registered", async () => {
  let c = net();
  assert.equal((await worker.fetch(reg("bad", { webhookUrl: "https://h", webhookToken: "t" }), env0())).status, 403);
  c = net({ serverId: "other" });
  assert.equal((await worker.fetch(reg("tok-a", { webhookUrl: "https://h", webhookToken: "t" }), env0())).status, 403);
  assert.equal(c.raft.filter(x => x.method === "PUT").length, 0);
});

test("register: webhook must be https with a token", async () => {
  net();
  assert.equal((await worker.fetch(reg("tok-a", { webhookUrl: "http://h", webhookToken: "t" }), env0())).status, 400);
  assert.equal((await worker.fetch(reg("tok-a", { webhookUrl: "https://h" }), env0())).status, 400);
});

test("two agents share the Worker, each forwarded to its own webhook only", async () => {
  const env = env0();
  await registered(env, "tok-a", "https://hook-a.example/x", "hook-token-a");
  await registered(env, "tok-b", "https://hook-b.example/y", "hook-token-b");
  const c = net();
  const ba = notice("na", A), bb = notice("nb", B);
  assert.equal((await worker.fetch(push(A, ba, sign(ba, await deriveSecret(MASTER, A, 1))), env)).status, 200);
  assert.equal((await worker.fetch(push(B, bb, sign(bb, await deriveSecret(MASTER, B, 1))), env)).status, 200);
  assert.deepEqual(c.hook.map(h => [h.url, h.init.headers.authorization, h.body]),
    [["https://hook-a.example/x", "Bearer hook-token-a", ba], ["https://hook-b.example/y", "Bearer hook-token-b", bb]]);
  // A's secret cannot push as B
  const x = notice("nx", B);
  assert.equal((await worker.fetch(push(B, x, sign(x, await deriveSecret(MASTER, A, 1))), env)).status, 401);
});

test("push: unknown agent, bad signature, wrong recipient -> 401, nothing forwarded", async () => {
  const env = env0(); await registered(env); const c = net();
  const b = notice("n1");
  assert.equal((await worker.fetch(push(B, b, sign(b, await deriveSecret(MASTER, B, 1))), env)).status, 401);
  assert.equal((await worker.fetch(push(A, b, sign(b, "x".repeat(64))), env)).status, 401);
  assert.equal((await worker.fetch(push(A, b, null), env)).status, 401);
  const w = notice("n2", B);
  assert.equal((await worker.fetch(push(A, w, sign(w, await deriveSecret(MASTER, A, 1))), env)).status, 401);
  assert.equal(c.hook.length, 0);
});

test("push: empty targets 200 not forwarded; duplicate forwarded once", async () => {
  const env = env0(); await registered(env); const c = net();
  const s = await deriveSecret(MASTER, A, 1);
  const e = notice("e1", A, []);
  assert.equal((await worker.fetch(push(A, e, sign(e, s)), env)).status, 200);
  const d = notice("d1");
  assert.equal((await worker.fetch(push(A, d, sign(d, s)), env)).status, 200);
  assert.equal((await worker.fetch(push(A, d, sign(d, s)), env)).status, 200);
  assert.equal(c.hook.length, 1);
});

test("push: target 500/network -> 503 retry; our key rejected -> 503 Retry-After 300, never 401", async () => {
  const env = env0(); await registered(env);
  const s = await deriveSecret(MASTER, A, 1);
  net({ hook: [500, new TypeError("net"), 401, 200] });
  const b = notice("r1");
  let r = await worker.fetch(push(A, b, sign(b, s)), env); assert.equal(r.status, 503); assert.equal(r.headers.get("retry-after"), "30");
  r = await worker.fetch(push(A, b, sign(b, s)), env); assert.equal(r.status, 503);
  r = await worker.fetch(push(A, b, sign(b, s)), env); assert.equal(r.status, 503); assert.equal(r.headers.get("retry-after"), "300");
  r = await worker.fetch(push(A, b, sign(b, s)), env); assert.equal(r.status, 200);
});

test("rotate: new secret registered; old accepted during grace; token can be updated without resending url", async () => {
  const env = env0(); await registered(env);
  const c = net();
  const r = await worker.fetch(reg("tok-a", { webhookToken: "hook-token-a2" }, { q: "?rotate=1" }), env);
  assert.equal(r.status, 200); assert.equal((await r.json()).generation, 2);
  const s1 = await deriveSecret(MASTER, A, 1), s2 = await deriveSecret(MASTER, A, 2);
  assert.equal(c.raft.find(x => x.method === "PUT").body.secret, s2);
  net();
  const b1 = notice("g1"), b2 = notice("g2");
  assert.equal((await worker.fetch(push(A, b1, sign(b1, s1)), env)).status, 200);
  const c2 = net();
  assert.equal((await worker.fetch(push(A, b2, sign(b2, s2)), env)).status, 200);
  assert.equal(c2.hook[0].init.headers.authorization, "Bearer hook-token-a2");
});

test("unregister: DELETE removes Raft registration and config", async () => {
  const env = env0(); await registered(env); const c = net();
  const r = await worker.fetch(reg("tok-a", null, { method: "DELETE" }), env);
  assert.equal(r.status, 200);
  assert.ok(c.raft.some(x => x.method === "DELETE"));
  assert.equal(env.RELAY._m.has("agent:" + A), false);
  const b = notice("u1");
  assert.equal((await worker.fetch(push(A, b, sign(b, await deriveSecret(MASTER, A, 1))), env)).status, 401);
});

test("never 404/410 on any path or method; insecure RAFT_SERVER refused", async () => {
  net();
  for (const r of [new Request(ORIGIN + "/"), new Request(ORIGIN + "/raft/push"), new Request(ORIGIN + "/raft/push/" + A), new Request(ORIGIN + "/x", { method: "POST" })]) {
    const s = (await worker.fetch(r, env0())).status;
    assert.ok(s !== 404 && s !== 410, "got " + s);
  }
  assert.equal((await worker.fetch(reg("tok-a", { webhookUrl: "https://h", webhookToken: "t" }), { ...env0(), RAFT_SERVER: "http://raft.example" })).status, 503);
});

test("logs never contain credentials, webhook tokens, or secrets", async () => {
  const env = env0(); const lines = []; const orig = console.log; console.log = s => lines.push(String(s));
  try {
    await registered(env);
    net({ hook: [500] });
    const b = notice("l1");
    await worker.fetch(push(A, b, sign(b, await deriveSecret(MASTER, A, 1))), env);
  } finally { console.log = orig; }
  const s1 = await deriveSecret(MASTER, A, 1);
  assert.ok(lines.length >= 2);
  for (const l of lines) for (const bad of ["tok-a", "hook-token-a", REG_KEY, MASTER, s1]) assert.ok(!l.includes(bad), `${bad} leaked`);
});
