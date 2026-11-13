# AGENTS.md — Raft Bot Relay Worker

This file is written for AI agents (and humans) who need to **deploy**, **configure**, **register with**, or
**change** this Cloudflare Worker. Read it fully before acting.

## What this is

Raft can push an external agent's inbox notices to an HTTPS URL. A notice is a small signed JSON body
(`raft-agent-inbox-notice.v1`) that says "this agent has new unread items in these conversations". It never contains
message content.

Many agent runtimes (for example a Cursor automation) only accept webhooks with `Authorization: Bearer <key>`, which
Raft's push does not send. This Worker sits in between:

```
Raft ──signed notice──▶ Worker /raft/push/<agentId> ──raw JSON + Bearer──▶ the agent's own webhook
                                                                            └▶ agent reads its Raft inbox and replies
```

One deployment serves any number of agents of one Raft server. Each agent registers itself.

## Security model (do not weaken)

- **Registration key.** Only callers holding the relay's registration key may register. The Worker stores only its
  SHA-256 (`REGISTRATION_KEY_SHA256`), so the Worker's configuration never reveals the key.
- **Agent identity.** The registering agent sends its own Raft agent credential. The Worker asks the fixed
  `RAFT_SERVER` (`GET /internal/agent-api/context`) who it belongs to and accepts only agents whose server id is
  `RAFT_SERVER_ID`. `RAFT_SERVER` is never taken from the caller (a caller-chosen server could claim any identity).
  The credential is used for that request only and never stored or logged.
- **Push secret.** Never stored and never shown to anyone: derived on demand as
  `HMAC-SHA256(MASTER_KEY, "raft-push:<agentId>:<generation>")` and registered with Raft by the Worker itself.
- **Webhook URL and token** (per agent) are stored in KV, AES-GCM encrypted with a key derived from `MASTER_KEY`,
  bound to the agent id. Never returned by any endpoint.
- **Isolation.** Each agent has its own push URL and secret; a notice signed for one agent is rejected for another,
  and a notice whose `recipientAgentId` differs from the URL's agent is rejected.
- **Logs** (`wrangler tail`) carry ids and outcomes only: no credentials, tokens, secrets or message content.

## Deploy (Cloudflare account owner, once)

Requirements: Node 20+, `wrangler` 4.x, a Cloudflare API token with **Workers Scripts: Edit** and
**Workers KV Storage: Edit** (or `wrangler login`).

```sh
npm i -g wrangler
export CLOUDFLARE_API_TOKEN=...            # from a file or secret store, never typed into chat or committed
export CLOUDFLARE_ACCOUNT_ID=...

wrangler kv namespace create RELAY         # put the returned id into wrangler.toml
# edit wrangler.toml: RAFT_SERVER_ID = your Raft server id (any agent of that server: `raft auth whoami` -> server.id)

# MASTER_KEY: random, generated straight into Cloudflare, never written anywhere else
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | wrangler secret put MASTER_KEY

# Registration key: generate, store only its hash in the Worker, hand the key to the agents' owner privately
KEY="rrk_$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf %s "$KEY" | sha256sum | awk '{printf "%s",$1}' | wrangler secret put REGISTRATION_KEY_SHA256
# deliver $KEY out of band (never in a shared channel), then: unset KEY

wrangler deploy                            # prints https://<name>.<subdomain>.workers.dev
npm test                                   # optional: unit tests, no network
```

Check the deployment without triggering any agent run:

```sh
U=https://<name>.<subdomain>.workers.dev
curl -s -X POST -H "X-Relay-Registration-Key: wrong" $U/raft/register          # 401 bad_registration_key
curl -s -X POST -d '{}' $U/raft/push/00000000-0000-0000-0000-000000000000        # 401 unknown_agent
curl -s -o /dev/null -w '%{http_code}\n' $U/                                     # 405 (never 404)
```

## Register an agent (run by the agent itself)

The agent needs, as environment variables or secrets (never printed, never posted):
`RELAY_REGISTRATION_KEY`, `RAFT_AGENT_TOKEN` (its own Raft agent credential), `MY_WEBHOOK_URL` (https),
`MY_WEBHOOK_TOKEN` (the Bearer key its webhook expects).

```sh
curl -sS -X POST "$RELAY_URL/raft/register" \
  -H "X-Relay-Registration-Key: $RELAY_REGISTRATION_KEY" \
  -H "Authorization: Bearer $RAFT_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "{\"webhookUrl\":\"$MY_WEBHOOK_URL\",\"webhookToken\":\"$MY_WEBHOOK_TOKEN\"}"
```

Success: `{"ok":true,"agentId":"…","name":"…","generation":1,"url":"…/raft/push/<agentId>","enabled":true,…}`.
The answer contains no secret and may be shared.

| Need | Call |
|---|---|
| Change only the webhook token (or URL) | same `POST`, body with just the changed field |
| New push secret | same `POST` with `?rotate=1` (the previous one is accepted for 10 more minutes) |
| Stop | `DELETE /raft/register` with the same two headers (removes the Raft push and the stored config) |

Errors: `401 bad_registration_key`, `401 missing_agent_credential`, `403 not_an_agent_of_this_server`,
`400 webhookUrl_https_and_webhookToken_required`, `502 raft_register_failed` (with `raftStatus`).

After registering, have someone @mention the agent once in Raft and confirm the agent reacts (or watch
`wrangler tail`: one line with `"action":"forwarded","status":200`).

## What the Worker answers Raft (and why)

| Case | Answer | Forwarded |
|---|---|---|
| Unknown agent, bad/missing `X-Raft-Signature-256`, wrong `recipientAgentId` | 401 | no |
| `targets` empty (also Raft's probe while push is switched off) | 200 | no — saves a paid agent run; the 2xx re-enables push |
| `noticeId` already forwarded (7 days) | 200 | no |
| Webhook answers 2xx | 200 | yes: raw body unchanged, `Authorization: Bearer <token>`, redirects not followed |
| Webhook 5xx, timeout (15 s), network error | 503, `Retry-After: 30` | Raft retries |
| Webhook rejects the token (401/403) | 503, `Retry-After: 300` | Raft retries; fix the token |
| Any other path or method | 405 | no |

Rules behind this table — keep them if you change the code:
- **Never answer 404 or 410.** Raft turns push off after three in a row.
- **Never pass the webhook's 401 back to Raft.** Repeated 401s also count against the registration; a broken
  webhook token must not look like a broken relay.
- **Retries belong to Raft.** The Worker stores no queue; it answers 503 so Raft retries with the latest merged
  notice. Each successful forward may start a paid agent run, so do not add retries that can double-forward.

## Operating notes

- Rotating the registration key: put a new hash; registered agents are unaffected.
- Rotating `MASTER_KEY` invalidates every push secret and every stored webhook token: all agents must register again.
- Raft push contract (source of truth): Raft Manual topic `external-agent`, section "Push notices".
- Tests: `npm test` (Node 20+, no dependencies; they never call real Raft or webhooks). Add a test with every change
  to the table above.
