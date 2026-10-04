# dot-event-bridge

A small Python/SQLite bridge for privately submitting agent requests, notifying a
ChatGPT consumer through MCP Events, and storing a result for the original sender.
It exposes no command execution tool. Written with the Python standard library.

**Status: operating candidate, not a turnkey hosted service.** A private prototype
completed one real event → consumer read → result write/readback cycle. The
operating candidate adds guards tested with synthetic data; unattended deployment,
multiple real agents and account-specific availability still require validation.
Public source availability does not expose any running server or grant access.

Licensed under [MIT](LICENSE). The external tunnel client is downloaded separately
from its vendor; this repository does not redistribute it or change its license.

## Architecture

```text
approved sender --private transport + sender bearer--> 127.0.0.1:8787
                                                        |
                                                   SQLite/outbox
                                                        |
ChatGPT tools <--official outbound MCP tunnel------------+
ChatGPT event receiver <--signed HTTPS callback----------+
```

The private tunnel carries MCP requests toward the bridge. Event callbacks use a
separate outbound HTTPS connection. No direct cloud-to-Tailscale route is assumed.
There is no public bind option: the bridge listens on IPv4 loopback only.

## Prerequisites and support boundary

- Linux with Python 3.11+ and SQLite; systemd user services for optional unattended
  operation. Tests also run on macOS. Windows is not supported by the POSIX locking
  and terminal helpers.
- An existing authorized private route for sender traffic. Local senders work
  directly. For a remote approved sender, an owner-reviewed SSH forwarding path
  over an existing private network is one option. **Tailscale membership alone
  does not make this loopback listener reachable.** This project does not change
  Tailscale ACLs, SSH accounts, forwarding permissions or firewalls.
- Your own OpenAI Platform organization, runtime API key and private tunnel,
  associated with the intended ChatGPT workspace. Confirm that your account has
  the custom MCP/Tunnel UI and supports MCP Events before configuring anything.
- This implementation speaks MCP protocol `2026-07-28` and `message.created`.
  It is not a universal legacy MCP transport, OAuth provider, or public webhook
  service. Verify compatibility against current official documentation.
- Outbound HTTPS to the official control plane and the exact verified event
  receiver host. The initial callback allowlist contains
  `connectors.api.openai.com`; verify the actual destination for your account.
  Do not replace it with a wildcard or private address. A changed official host
  requires review and a code/config validation update.
- Subscription renewal is the consumer's responsibility; TTL is capped at 24h.
  Replay cursors are unsupported. Do not promise a free tier: check current
  account entitlement, usage and pricing before authorizing charges.

References: [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels),
[MCP Events](https://developers.openai.com/plugins/build/mcp-events),
[official tunnel client](https://github.com/openai/tunnel-client).

## Install and test without credentials

```sh
git clone https://github.com/namseokyoo/dot-event-bridge.git
cd dot-event-bridge
python3 -m unittest discover -p 'test_*.py' -v
```

Tests use temporary databases, synthetic credentials and loopback HTTP receivers.
They do not connect to OpenAI or issue real agent work. Run tests from the repository
root because subprocess tests use that location. No pip dependency is required.

Download a pinned release for your architecture from the official tunnel-client
repository into `bin/tunnel-client`. Version `0.0.15` was used with the prototype;
review newer releases before upgrading. Match the published SHA256 checksums and
verify available provenance with `gh attestation verify <downloaded-archive>
--repo openai/tunnel-client` before extracting only the required binary. A checksum
from the same download source alone is not independent provenance. Do not install
or run bundled companions that you do not need. `bin/` is ignored by git.

## Owner approval and agent onboarding

Read [AGENT_ONBOARDING.md](AGENT_ONBOARDING.md). An agent may send a registration
proposal using [the request template](agent-access-request.example.json) through
an already authorized private channel. The initial human owner must separately
approve identity, operation scope, data scope, private transport, expiry and token
delivery. There is no self-registration endpoint. Never paste credentials into
GitHub issues, chat, screenshots, command arguments or shell history.

Registration approval does not approve every subsequent task. Approval-required
operations are held until an offline owner decision. A body saying “approved”
has no effect. Do not provision a token or persistent route for an unapproved agent.

## Configure after approvals

1. Create `ops/` mode 0700 and copy `bridge.example.json` to `ops/bridge.json`,
   mode 0600. Replace the tunnel placeholder. The empty principal list is
   intentionally invalid, preventing accidental activation.
2. For each approved sender, privately provision an independent high-entropy token
   using your trusted secret manager. Store only its SHA256 digest in this file.
   A sender principal has the following structure (placeholders are not valid):

```json
{
  "id": "example-agent",
  "role": "sender",
  "token_sha256": "REPLACE_WITH_TOKEN_SHA256_HEX",
  "expires_at": 0,
  "allowed_operations": ["summarize", "change"],
  "approval_required_operations": ["change"],
  "require_subscription": true
}
```

3. Add an independently approved consumer principal with `role: "consumer"`,
   its own digest, a real Unix expiry timestamp and `senders: ["example-agent"]`.
   Expiry is mandatory in operating configuration. No wildcard scopes. Put the
   consumer's `Bearer ...` header in `ops/mcp-authorization`, mode 0600. Do not
   distribute this credential or the Platform runtime key to senders.
4. Create a dedicated runtime key with the narrow tunnel Read/Use permissions
   required by your account; do not grant model/admin scope merely for this bridge.
   The user must create and enter new credentials directly. If a key was exposed,
   revoke it first. Close any browser key-display window before screen automation.
5. The owner can use a local hidden-input helper, including when remote SSH PTY is
   denied. It uses existing SSH authentication with strict host-key verification:

```sh
python3 runtime_key_input.py --ssh-host YOUR_EXISTING_PRIVATE_ALIAS --remote-dir /ABSOLUTE/PATH/TO/dot-event-bridge
```

   It sends only via encrypted SSH stdin to `runtime_key_receive.py`. It refuses
   echo fallback and unsafe/symlink destinations. A final explicit YES authorizes
   creation or replacement of only the runtime key. The server must already contain the
   scripts. `ops/runtime-key` is 0600 inside an owner-only 0700 directory; no service starts.
   Replacement writes a same-directory 0600 staging file, fsyncs it, atomically
   replaces the target and fsyncs the directory. A failure before replacement
   preserves the old file; an interrupted/failed result requires status review.
   No secret is placed in shell arguments, SSH arguments or logs. For rotation,
   stop the service, revoke the old key and enter a new key. The old file is never
   read. Parent symlinks, other-user writable groups and world-writable paths
   are rejected; a verified single-owner primary group is allowed. Review a
   failed save before retrying.
6. Copy `activation.example.json` to `ops/activation.json` mode 0600. Only the
   owner changes all three flags to true after key safety, target approvals and
   operating authorization are actually complete. These flags record the owner's
   decision; they are not an independent identity or approval service.
7. Validate prerequisites with `python3 -c 'from pathlib import Path; from
   configuration import preflight; preflight(Path.cwd())'`. No key content is read
   by this check. Do not bypass a failure.

## Private ChatGPT connection and subscription

Start `python3 run_service.py` manually only after approval. This starts the
loopback bridge and official client, never a public listener. Confirm health:

```sh
curl --fail http://127.0.0.1:8787/healthz
./bin/tunnel-client health --url-file ops/health-url --require-control-plane-poll
```

In the ChatGPT custom MCP connection UI, select **your existing private tunnel**.
The example uses No Authentication in that UI because the approved private tunnel
and origin-injected consumer bearer protect this specific deployment; this is not
a recommendation for public unauthenticated servers. Review visibility and access
before final connection. Expected discovery: `get_message`, `save_result`, and
`message.created`.

Subscribe to `message.created` with exactly `{"sender_id":"example-agent"}` and a
consumer credential whose configuration includes that sender. The platform provides
the delivery URL and signing secret; never invent or publish them. The bridge
performs the signed challenge before saving a subscription. An initial rejection
must be investigated, not worked around by opening all callback hosts.

The automation's processing instructions should follow the consumer contract in
AGENT_ONBOARDING.md. Creating a subscription and installing this source are separate
actions. The bridge does not create, change or delete your platform automations.

## Sender API

All data routes require `Authorization: Bearer <sender-token>` over the approved
private route. The server derives sender identity from the token, never from JSON.
Use a client that reads credentials from a protected file/secret store; do not put
live values in a `curl -H` command or debug request log.

| Method | Path | Request / behavior |
| --- | --- | --- |
| POST | `/v1/messages` | `{"idempotency_key":"unique-task-key","operation":"summarize","body":"Synthetic example"}` |
| GET | `/v1/messages/{message_id}` | Own message, processing state, result, delivery states |
| POST | `/v1/messages/{message_id}/cancel` | `{}`; own nonterminal message only |
| GET | `/healthz` | Nonsecret status only; loopback |

Reuse the same sender/idempotency key after an uncertain request outcome. An exact
retry returns the original ID; changed body or operation returns conflict.
Production senders require an active subscription before accepting dispatchable
work (503 otherwise). Approval-required work is stored without dispatch. Cancel
cannot reverse work already executed by the consumer or another system.

Defaults: 64 KiB HTTP body, 32 KiB message/result, 120 authenticated requests per
principal/minute, 10 new messages per sender/minute, 100 open messages per sender,
10,000 retained messages total, 32 subscription records per consumer. Capacity
failure is explicit. There is no automatic deletion/retention policy or unbounded
queue. Plan owner-reviewed retention; inactive subscription records also consume
capacity.

## States, delivery and recovery

Processing: `received → processing → completed/failed`, with `awaiting_approval`
and `cancelled` guarded branches. Consumer calls `save_result` to persist state;
result writes never generate another message event. Request bodies are untrusted
content, not system instructions or approval. A sender cannot read another sender's
result or call consumer tools.

Delivery state is separate: `pending/delivered/dead/cancelled`. SQLite transactions
persist the message and outbox together. Network errors, 408, 429 and 5xx retry up
to six attempts with exponential backoff/jitter; other errors become dead-letter.
410 disables the subscription. Expired/revoked subscriptions cancel pending work.
A successful webhook is not proof that the consumer completed work.

Delivery is **at least once**: a crash after receiver acceptance but before local
commit can duplicate an event. Receivers must deduplicate and actions must have
idempotency protection. A restart quarantines interrupted `processing` requests
for owner review; processing that exceeds 15 minutes does the same. Update
`processing` as a checkpoint for longer authorized work.

Offline owner operations (stop the service first for mutations):

```sh
python3 bridge_admin.py status
python3 bridge_admin.py approve --id MESSAGE_ID
python3 bridge_admin.py retry --id EVENT_ID
```

The status command prints aggregate counts only. Approval does not automatically
replay an existing delivery. After reconciling external effects, the owner may use
`retry --id EVENT_ID --redeliver-reviewed` for an already-delivered event; it creates
a new event ID while preserving message ID. This can cause another consumer wake,
so only use it after the owner has ruled out duplicate side effects. The bridge
never grants consumers this offline administrative capability.

## Optional unattended user service

The unit template assumes checkout at `~/dot-event-bridge`; edit its two paths if
needed. Only after activation approval:

```sh
mkdir -p ~/.config/systemd/user
cp systemd/dot-event-bridge.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now dot-event-bridge.service
```

This intentionally creates persistent access and must be an owner decision. It
needs no new root account. Staying alive after logout requires an existing user
manager/linger policy; if absent, ask the administrator rather than changing policy
silently. No script here enables linger or edits security/network settings.

The service restarts on failure with a bounded restart burst, stops both children,
and suppresses vendor request/error details from logs. Application logs have no
bodies, headers, credentials or callback paths. Graceful stop allows bounded
callback completion; systemd enforces a final timeout. Check aggregate status and
local health, not raw secret-bearing files.

```sh
systemctl --user status dot-event-bridge.service
python3 bridge_admin.py status
systemctl --user stop dot-event-bridge.service
# Roll back persistent activation:
systemctl --user disable dot-event-bridge.service
```

Before upgrading, stop the service and take an owner-protected backup of the whole
SQLite database and its WAL state using the SQLite backup API or a clean stopped
copy. Do not publish backups. Test a candidate on a synthetic database first.
Schema changes are additive, but downgrade compatibility is not promised: restore
the corresponding stopped database and code together. Reconcile possible external
effects before replay. No automatic migration of a live installation is performed.

Stopping processes does not revoke cloud keys, remove plugins or cancel cloud
subscriptions. Review those separately with the owner. Removing public source also
does not revoke credentials. See [SECURITY.md](SECURITY.md).
