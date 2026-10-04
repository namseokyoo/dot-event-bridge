# Security and disclosure

Do not put vulnerabilities containing live credentials or personal deployment
information in public issues. Contact the repository owner through an established
private channel; if no private channel is available, post only a non-sensitive
request for contact. No monitored security mailbox or response SLA is promised.

Keep `ops/`, data, logs, backups, runtime binaries and `.env` files out of git.
The ignore file is a convenience, not a security boundary. Before publishing any
fork, inspect every tracked file and the complete history; use a secret scanner
and inspect high-entropy findings. A clean latest commit cannot remove a secret
from earlier history. This repository originated from an explicit source allowlist
and a new history, not an exported operating directory.

Use one expiring sender token per approved agent and a separate consumer token.
Keep only sender/consumer SHA256 digests in bridge configuration. The tunnel
runtime key must be a dedicated restricted key and is consumed only by the official
client. Revoke any exposed key; removing a log or hiding a UI is not revocation.
Do not let screen automation observe a browser key-creation modal.

The project prevents cross-sender access through authenticated IDs and declared
operation policies. It does not sandbox a consumer's external tools, prove human
identity from message text, encrypt SQLite at rest, or make an untrusted host safe.
The deployment owner and processes under the same Unix account can access local
state. Use protected disks and restrict the account appropriately.

Callbacks require exact allowlisted HTTPS hosts and public DNS results. Resolved
IP connections are pinned while preserving TLS hostname verification; redirects
and proxies are not followed. Signing secrets are stored in the private database
for deliveries and rotation, never included in events or logs. Input limits and
per-principal quotas reduce resource abuse, but this single-process loopback
server is not designed to defend a public Internet endpoint. Slow local clients
or callbacks can delay other work; do not expose it publicly.

No code here opens public ports, configures a VPN, provisions remote accounts,
installs a system service, enables linger, or contacts new agents automatically.
Owner-controlled approval flags document decisions; anyone with write access to
those files already has administrative authority over this deployment.
