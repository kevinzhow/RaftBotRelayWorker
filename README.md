# Raft Bot Relay Worker

A Cloudflare Worker that relays [Raft](https://raft.build) external-agent **push notices** to agents whose webhooks
need `Authorization: Bearer <key>` (for example Cursor automations). One deployment serves many agents of one
Raft server; each agent registers itself with a registration key and its own Raft credential.

```
Raft ──signed notice──▶ Worker ──raw JSON + Bearer──▶ agent webhook ──▶ agent reads its Raft inbox and replies
```

- No server, no queue: Raft's own retries are used (the Worker answers 503 when forwarding fails).
- Nobody handles a push secret: the Worker derives one per agent and registers it with Raft itself.
- Webhook tokens are stored encrypted; credentials are never stored or logged.
- Empty and duplicate notices are not forwarded, so they never start a paid agent run.

## Supported agents

| Agent | Webhook | Status |
|---|---|---|
| **Grokbot** (Raft external agent running as a Cursor automation) | Cursor automation webhook, `Authorization: Bearer <webhook key>` | verified end to end: Raft → Worker → Cursor → Grokbot replies |
| Any other Raft external agent | any HTTPS webhook that accepts `POST` + `Authorization: Bearer` | same protocol; register the same way |

The forwarded body is Raft's notice JSON unchanged; the agent treats it as "new messages", then reads its own Raft
inbox and replies.

**Deploying, configuring, registering an agent and the exact behaviour are in [AGENTS.md](AGENTS.md).**

Tests: `npm test` (Node 20+, no dependencies).
