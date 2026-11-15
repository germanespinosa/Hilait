# Hilait codebase reference

A working map of the Hilait repository for future development. It describes
how the code is organized, how the pieces talk to each other, where state
lives, and the invariants that changes must preserve. The user-facing
behaviour is documented in [README.md](../README.md); credential handling is
documented in [CREDENTIAL_SECURITY.md](CREDENTIAL_SECURITY.md).

*Last reviewed for package version **0.1.46** (terminal truecolor fix),
2026-11-14.* Update this file
whenever a change alters the architecture, an API, a stored file, or an
invariant listed below.

---

## 1. What Hilait is

Hilait is a **human-in-the-loop SSH workspace** written in Python (FastAPI +
Paramiko) with a vanilla-JS browser UI. One server process:

1. Holds all SSH credentials (encrypted at rest) for a set of saved machines.
2. Gives the human a browser workspace: xterm.js terminals, an SFTP file
   pane, settings, audit logs.
3. Lets AI agents reach those machines **only** through a token-bound MCP
   bridge (`hilait mcp`). Agents never see hostnames, usernames, or secrets.
   Every agent session needs a human-approved *grant* that states a purpose,
   a file scope, and (on tiered machines) a privilege tier.
4. Records everything in an encrypted, hash-chained audit log and can have an
   LLM score each agent session for safety / purpose alignment / correctness,
   optionally auto-revoking access on low scores.
5. Optionally pushes approval requests and review alerts to a phone via ntfy.

It is the cross-platform successor of the Windows-only
[HilaitWin](https://github.com/germanespinosa/HilaitWin).

---

## 2. Repository layout

```
pyproject.toml            Package metadata (hatchling), deps, `hilait` console script, pytest config
package.json / build.mjs  esbuild bundle of xterm.js + addons and JetBrains Mono fonts (Node only needed to rebuild)
deploy/hilait.service     Hardened systemd unit (dedicated user, LoadCredential master key, sandboxing)
docs/CREDENTIAL_SECURITY.md  Threat model, at-rest encryption table, Linux service migration
docs/CODEBASE.md          This file
design/icon-concepts/     Logo explorations + generate.py (not shipped)
licenses/, THIRD-PARTY-NOTICES.md  Bundled third-party licenses (force-included into the wheel)
.github/workflows/ci.yml  pytest + wheel build on ubuntu/windows/macos × Python 3.11/3.12

src/hilait/
  __init__.py      __version__ (keep in sync with pyproject.toml)
  cli.py           `hilait serve | mcp | otp reset`
  server.py        FastAPI app factory, Runtime wiring, all HTTP/WebSocket routes, agent tool dispatch, managed sudo
  storage.py       Store (encrypted JSON files, master key, agents) and Audit (hash-chained encrypted records)
  admin_auth.py    TOTP (RFC 6238) login, browser sessions, OTP seed lifecycle, rate limiting
  sessions.py      SSH sessions (Paramiko PTY), host-key trust policy, output buffer, screen snapshots
  files.py         Audited SFTP operations and collision-safe copy/upload/download
  transfers.py     Hilait-managed server transfer folders (root setting, per agent/machine/tier folders, admin browse API)
  agents.py        Grants, tiers (legacy/normal/elevated), standing authorizations, idle timeout
  enrollment.py    Remote agent self-enrollment requests (claim-secret protected)
  mcp_server.py    stdio MCP bridge run on the agent's machine; forwards to /agent/{tool}
  review.py        LLM activity review: evidence building, prompts, provider streaming, result validation
  ntfy.py          ntfy push for pending approvals and low review scores
  tls.py           Persistent self-signed certificate for `--lan` HTTPS
  static/          Browser UI (no framework, no build step except the xterm bundle)
    index.html     Main workspace shell (CSP: self only); {{VERSION}}/{{BUILD}} substituted by server
    app.js         Entire workspace UI (~100 KB IIFE): login, machines, sessions, settings dialogs, logs, reviews
    app.css, theme.css, theme.js   Styling and light/dark mode (theme.js runs before paint)
    terminal-entry.js  Source for vendor/xterm.js bundle; exposes window.HilaitTerminal(+Appearance)
    terminal.css   Terminal pane styling
    approve.html/.js/.css  Mobile approval page opened from ntfy links (/approve/{grant_id})
    vendor/        Built xterm.js + xterm.css (committed; rebuilt with `npm run build`)
    fonts/         JetBrains Mono woff2 subsets (copied by build.mjs)

tests/                    pytest (asyncio_mode=auto); real loopback SSH via asyncssh fixture
```

Size guide: `server.py` ~1,000 lines, `storage.py` ~600, `agents.py` ~400,
`review.py` ~400, `app.js` ~680 very long lines. There are no
sub-packages.

---

## 3. Runtime architecture

```
 Browser (index.html/app.js)                     Agent machine
   │  HTTP  Authorization: Bearer <session>        hilait mcp  (stdio MCP server)
   │  WS    /ws/events, /ws/terminal/{id}            │  HTTP POST /agent/{tool}
   ▼        (first message = {"type":"auth"})        ▼  Bearer <agent token>
 ┌──────────────────────── FastAPI app (server.create_app) ───────────────────────┐
 │ Runtime                                                                         │
 │  store  : Store          ── encrypted files in data dir                         │
 │  auth   : AdminAuth      ── admin token / OTP sessions                          │
 │  audit  : Audit          ── activity-records/<generation>/<shard>/<seq>.audit   │
 │  sessions: SessionManager ─ Paramiko SSHClient + PTY channel per session        │
 │  files  : FileService    ── SFTP over a session's client                        │
 │  transfers: TransferArea ── server-side transfer root and per-grant folders     │
 │  agents : AgentRuntime   ── grants, authorizations, idle loop, event fan-out    │
 │  enrollment: AgentEnrollment                                                    │
 │  ntfy   : NtfyNotifier   (agents.on_pending → ntfy.notify_pending)              │
 │  reviewer: Reviewer      ── LLM review                                          │
 │  sudo_requests / sudo_consents (in-memory)                                      │
 │ Background tasks (lifespan): agents.idle_loop (5 s), automatic_reviews (30 s),  │
 │                              activity_retention (hourly)                        │
 └─────────────────────────────────────────────────────────────────────────────────┘
                     │ SSH (Paramiko, host key pinned by SHA-256)
                     ▼
               Saved machines
```

Key wiring facts:

* `Runtime.__init__` builds every service from one `Store`. Tests construct
  `create_app(tmp_path)` or `Runtime(tmp_path)` directly.
* `AgentRuntime._notify(event)` is the single fan-out for UI events; every
  `/ws/events` socket registers an `asyncio.Queue` in
  `runtime.agents.notifications`. Event types include `request`, `access`,
  `profiles`, `authorizations`, `session_opened`, `session_closed`,
  `sudo_request`, `review_progress`, `agent_token_request/approved/denied`.
  The UI generally reacts by re-fetching `/api/state`.
* `SessionManager.on_close` is set by `AgentRuntime` so a closed SSH session
  moves its grant to `Closed`.
* Blocking Paramiko and file I/O runs via `asyncio.to_thread`.
* Errors map to HTTP codes through exception handlers: `KeyError→404`,
  `ValueError→400`, `PermissionError→403`, `RateLimitError→429`,
  `HostKeyApprovalNeeded→409` (body carries host, fingerprint, previous).
  Domain code raises these built-ins rather than `HTTPException`.

---

## 4. Authentication layers

| Who | Credential | Checked by |
| --- | --- | --- |
| Human, before OTP | Admin token (random, encrypted in `admin.token`; printed on `serve`; `--open` passes it via `#token=` fragment) | `AdminAuth.valid` |
| Human, OTP enabled | 6-digit TOTP → 12 h in-memory session token (SHA-256 kept). Admin token is then **rejected** (403 `otp_required`). Sessions die on restart. 5 bad codes / 5 min → 429. Codes cannot be replayed (`last_step`). | `AdminAuth.verify_login/valid` |
| Agent | 64-hex token; `agents.json` stores SHA-256 hash + encrypted copy | `Store.agent_for_token` |
| Enrolling agent | Private `claim` secret returned once by `POST /api/agent-enrollment` | `AgentEnrollment.status` |

WebSockets check `Origin == http(s)://Host` and require the first message to
be `{"type":"auth","token":...}`; validity is rechecked every message and at
least every 5 s (close code 4401). Tokens are never put in URLs (a previous
version did; see CREDENTIAL_SECURITY.md).

`hilait serve` refuses non-loopback `--host`; network exposure is only via
`--lan`, which binds `0.0.0.0` with the self-signed cert from `tls.py`.

Many admin actions additionally require OTP to be **enabled** (not merely a
valid session): saving profiles, approving/rejecting agent enrollment, and
agent enrollment itself.

---

## 5. Persistent state (data directory)

Location: `HILAIT_DATA_DIR` (must be absolute) or
`platformdirs.user_data_path("Hilait","Hilait")`. Directory must be owned by
the process user with mode 0700; every secret file must be a regular,
single-link, 0600 file (`_private_file` / `_private_directory`; POSIX checks
skipped on Windows). Writes are atomic (temp file + fsync + `os.replace`).

Master key: Fernet key from `HILAIT_MASTER_KEY_FILE`, else
`$CREDENTIALS_DIRECTORY/master.key` (systemd), else `<data>/master.key`
(auto-created). If an external key is configured, a leftover
`<data>/master.key` is a hard error.

| File | Accessor | Encryption | Contents |
| --- | --- | --- | --- |
| `master.key` | Store init | — | Fernet master key (convenience mode only) |
| `admin.token` | `Store.admin_token` | master | Admin recovery token (legacy plaintext auto-migrated) |
| `admin-otp.json` | `read/write_secure` | master | `seed`, `last_step`, `pending_seed` |
| `connections.json` | `Store.profiles()` | **OTP-seed key** | Saved machine profiles (see §6) |
| `known-hosts.json` | `read/write` | OTP-seed key | `"[host]:port" → "SHA256:..."` |
| `authorizations.json` | `read/write` | OTP-seed key | Standing agent↔machine authorizations |
| `agents.json` | `read/write` | plaintext JSON (token encrypted inside) | Agent identities |
| `agent-enrollment.json` | secure | master | Enrollment requests (pruned 24 h after decision) |
| `ntfy.json` | secure | master | ntfy settings + token |
| `review-settings.json` | `read/write` | plaintext JSON, `api_key` encrypted | Review provider/model/thresholds |
| `reviews.enc`, `review-alerts.enc` | secure | master | Review results; per-grant alerted scores |
| `review-revocations.json` | plaintext | — | Grant → `reviewed_utc` already acted on |
| `activity-settings.json` | plaintext | — | Activity folder + `retention_days` |
| `activity-records.current` | — | — | 32-hex active audit "generation" |
| `activity-records/` (movable) | `Audit` | master | Audit records (see §9) |
| `transfer-settings.json` | `TransferArea` | plaintext | Optional transfer root override |
| `lan.crt`, `lan.key` | `tls.py` | key PKCS#8-encrypted with HMAC(master, "Hilait LAN TLS private key v1") | LAN HTTPS identity |

`CONNECTION_FILES` (`connections`, `known-hosts`, `authorizations`) use a
Fernet key = SHA-256("Hilait connection records v1\0" + OTP seed bytes).
Consequences that must be preserved:

* No connection data can be saved until OTP is configured.
* First OTP setup migrates legacy plaintext connection files; **replacing
  or disabling OTP, or `hilait otp reset`, discards them** (UI warns; all
  sessions must be disconnected first).
* Agent grants on profiles that disappear are revoked after key replacement.

**Transfer root** (outside the data dir): saved setting, else
`HILAIT_TRANSFER_DIR` (absolute), else `<data dir>-transfers` as a sibling
(`/var/lib/hilait-transfers` for the systemd unit, which lists it in
`StateDirectory=`). It must be a private (0700, owned) non-symlink folder
outside the data and activity folders. Layout:
`<root>/<agent-slug>-<agent id[:8]>/<machine-slug>-<profile id[:8]>/<tier>`,
each level 0700. Files there are **not encrypted**; they are ordinary files
the agent copied or the admin staged.

On the agent side, `hilait mcp` keeps its token/pending claim in
`<user data>/Hilait/agent-clients/<sha256(server url)>.json` unless
`HILAIT_AGENT_TOKEN` is set.

---

## 6. Machine profiles and access tiers

A profile (in `connections.json`) contains: `id, name, host, port, username,
platform (unix|windows), shell (default|powershell7|powershell5),
auth_method (password|key), private_key (server-side path), secret,
sudo_policy, sudo_secret, allowed_agent_ids (null = all agents),
agent_idle_timeout_minutes (default 10, 0 = off), access_mode
(legacy|tiered), normal_unprivileged_confirmed, elevated_username,
elevated_auth_method, elevated_private_key, elevated_secret,
elevated_sudo_secret, elevated_sudo_policy, elevated_allowed_agent_ids
(explicit list, default empty), credential_revisions {legacy, normal,
elevated}`.

* `Store.public_profile` strips secrets (adds `has_saved_*` flags);
  `public_profile(agent=True)` exposes only id, name, platform, shell,
  capabilities.
* **Tiers**: `legacy` (single account; existing profiles), or for `tiered`
  Unix profiles `normal` (must be an account that cannot escalate — human
  confirms, Hilait cannot enforce) and `elevated` (separate account).
  `agents.resolve_privilege` validates; `agents.login_profile` produces the
  per-tier login view (elevated swaps in `elevated_*` fields; normal drops the
  sudo secret).
* `save_profile` (server.py) is the most intricate endpoint: it preserves
  secrets across edits, clears the secret when the auth method changes,
  requires reconfirmation if the normal username changes, refuses to change
  credentials/tier while affected sessions are open, bumps
  `credential_revisions` for changed tiers, and then revokes authorizations
  and grants that are no longer valid.
* Sudo policy values: `per_request | per_connection | per_authorization |
  never` (the last means "use saved password without asking").

---

## 7. Agent access lifecycle

### Identity
* Created by the admin (`POST /api/agents` → MCP config with
  `HILAIT_AGENT_TOKEN` env), **or** self-enrolled remotely:
  `request_agent_token(name, reason)` → `POST /api/agent-enrollment`
  (requires OTP enabled; 20–1000-char reason; 5 req / 10 min per IP, 20
  pending max) → admin approves in Agent Access choosing visible machines →
  `agent_token_status()` retrieves the token with the claim and stores it
  locally. Requests expire after 10 minutes.
* `GET /.well-known/hilait` advertises the MCP command and enrollment
  endpoints.

### Grants (`agents.Grant`)
States: `Pending → Approved ⇄ Paused → {Denied, Expired, Revoked, Closed}`
(`ENDED` set; ended grants can never resume). Grants are **in memory only**
(lost on restart; audit retains history).

1. `request_access(connection, purpose, fileAccess, privilege)` — purpose
   80–8000 chars; scope `None < Remote < LocalTransfers`; ≤3 pending per
   agent, ≤20 total. Audited as `access_requested`.
2. If an active standing authorization exists for (agent, machine, tier)
   with a scope ≥ requested, it auto-approves.
3. Otherwise the UI shows the request and ntfy (if enabled) sends
   approve/deny links to `/approve/{grant_id}`. Pending requests expire after
   10 minutes (checked lazily in `pending()`/`owned()`).
4. Approval (`AgentRuntime.approve`) opens a **new** SSH session for that
   grant (never reuses or promotes one), re-validates permissions and
   `credential_revision` after the connection opens (race guard). For
   `LocalTransfers` it calls `TransferArea.folder_for(agent, profile, tier)`
   to create/reuse the grant's server folder (never a typed path) and stores
   it as `grant.local_folder` (agent sees `localFolder`). It optionally
   creates/updates a timed (≤8760 h) or permanent authorization. Elevated
   approval requires `elevated_confirmed: true`.
5. Human controls: pause, takeover (sets `human_controlled`, pauses idle
   timer), resume, revoke (closes session).
6. Agent finishes with `release_access(closeConnection=true)`.
7. `idle_loop` closes sessions idle longer than the profile timeout.

`AgentRuntime.owned(identity, grant_id, active=, files=, local=)` is the
authorization gate for every operational tool; file operations re-run it as
a `guard` after acquiring the session's file lock.

### Standing authorizations
Records in `authorizations.json`: `id, agent_id, profile_id, connection,
expires_utc | permanent, privilege, credential_revision, file_access,
revoked`. (Records from ≤0.1.43 may still carry an ignored `local_folder`;
it is dropped when the record's file access is updated.) `active_authorizations()` filters out revoked,
expired, agent-inactive, tier-disallowed, or credential-revision-stale
entries. Revocation keeps the record (audit history).

### MCP tools (`mcp_server.py` → `server.run_agent_tool`)
`request_agent_token`, `agent_token_status`, `connections`,
`request_access`, `access_status`, `release_access`, `terminal_write`
(exactly one of text/base64; returns output since the write),
`terminal_read(cursor)`, `terminal_screen` (asks an open browser terminal for
a rendered snapshot within 2 s, else ANSI-stripped last ~80 lines),
`files(action=list|stat|read|write|mkdir|rename|delete|chmod|symlink)`,
`copy(direction=remote|upload|download)`, `request_sudo(command, reason)`.
Every tool result for access includes the "NO SHENANIGANS" warning
(`AGENT_WARNING` / `ELEVATED_WARNING`). The bridge allows HTTP only on
loopback; `--ca-cert` / `HILAIT_CA_CERT` trusts a self-signed LAN cert. A
403 "invalid or revoked" clears the cached token.

### Managed sudo (`server._sudo`)
Disabled for `normal` grants and Windows. Pauses the grant, emits a
`sudo_request` UI event, waits up to 600 s for `/api/sudo/{id}/decide`, then
runs `/usr/bin/sudo -k -S -p '' /bin/sh -lc <quoted cmd>` on a **separate
exec channel** feeding the password on stdin. Output is audited, appended to
the visible terminal buffer, and returned (≤256 KiB). The password never
reaches the agent. Consent caching is per grant or per authorization
depending on `sudo_policy` (`runtime.sudo_consents`, in memory).

---

## 8. SSH sessions and files

* `SessionManager.open` connects with Paramiko (`allow_agent=False,
  look_for_keys=False`, 20 s timeouts) using `_TrustPolicy`: an unknown or
  changed host key raises `HostKeyApprovalNeeded` → 409 → UI asks the human
  → `POST /api/hosts/trust`. Credentials are sent only after the key matches.
* PTY: `xterm-256color`, 100×30 initial; Windows PowerShell choice sends a
  startup command (`_shell_start_command`).
* Output buffer: 2 MiB rolling `bytearray` with `base_cursor`; `read(cursor)`
  reports a `gap` if the cursor fell off the buffer. Every chunk is audited
  as `terminal_output`. Agent input audited verbatim
  (`terminal_input_sent`); **human input is redacted** to its length.
* `files.remote_path` requires absolute paths, forbids `..` and NUL, and
  normalizes Windows paths (`C:\x` → `/C:/x`, rejects reserved names).
  `local_path` confines LocalTransfers to the grant's Hilait transfer
  folder; agents give that side as a path relative to it.
* Read/write chunks ≤256 KiB. Writes never overwrite unless
  `overwrite=true` on an existing file. Copies never overwrite, refuse
  symlinks, cap depth at 64, and write via `.part` temp + rename.
* Cross-tier remote copies by agents are refused.

---

## 9. Audit log (`storage.Audit`)

* Each record `{sequence, utc, kind, context, data, previous}` is
  JSON → Fernet(master) → base64, stored as one file
  `<activity dir>/<generation>/<(seq-1)//1000 :08d>/<seq :016d>.audit`.
  `previous` = SHA-256 of the prior file's bytes (hash chain). Writes use a
  temp file + `os.link` (no overwrite) + directory fsync.
* `generation` (32 hex, in `activity-records.current`) lets
  `delete_session` and retention `prune` rewrite the whole chain into a new
  generation and atomically switch; orphan generations are removed at
  startup. Legacy single-file `activity.audit` is migrated and removed only
  after validation.
* In-memory indexes (`_grants`, `_summaries`, `_grant_last`, `_hashes`) make
  `session(grant_id)` and log summaries cheap; `session()` re-verifies each
  record's hash and links.
* Activity folder can be moved (`update_settings`): copy to a staging dir,
  verify, rename into an empty private target; key and index stay in the
  data dir. Retention: `None` (forever) or 1–3650 days; deletes only whole
  sessions whose last activity is older, never active or under-review ones,
  plus old non-session records; also prunes review files.
* Common `kind`s: `session_opened/closed/error`, `terminal_output`,
  `terminal_input_sent`, `human_terminal_input`, `file_request/result/error`,
  `copy_completed`, `access_requested`, `access_state_changed`,
  `sudo_requested/output`, `automatic_approval_*`, `agent_token_*`,
  `notification_*`, `activity_reviewed`, `review_access_revoked`,
  `agent_idle_timeout`, `session_log_deleted`, `activity_retention_applied`,
  `transfer_settings_changed`, `transfer_file_uploaded/downloaded`,
  `transfer_item_deleted`.

---

## 10. Activity review (`review.py`)

* Providers: `local` (Ollama/OpenAI-compatible; native `/api/chat` when the
  endpoint ends in `/api` or is `:11434` without `/v1`), `openai`,
  `anthropic` (`/messages`, `x-api-key`, `anthropic-version: 2023-06-01`),
  `grok` (model list at `/language-models`). Hosted providers must be HTTPS.
  All calls stream; response capped at 1 MiB; evidence capped at 400 KB.
* **Light** review sends the stated purpose + agent inputs/requests (with a
  short preceding prompt/menu excerpt from `_prompt_context`), scores
  `safety` and `purpose_alignment`. **Deep** adds outputs and file results
  and scores `correctness`.
* Results are strictly validated (integers 0–10, rationales, summary ≤500,
  ≤8 findings with labels wrong|unnecessary|problematic|dangerous,
  evidence_refs limited to real sequences) and cached by
  `evidence_hash` + level + provider + model + `REVIEW_SCHEMA_VERSION` (3).
  Bump the schema version when the prompt/result format changes.
* `server._run_review` applies thresholds after each review:
  `alert_thresholds` → ntfy alert (only for newly lower scores);
  `revoke_thresholds` (normal/legacy) / `elevated_revoke_thresholds` →
  revoke matching authorizations and grants for that agent+machine+tier and
  close sessions; `revoke_all_tiers_on_safety` widens a safety trigger to
  all tiers. `review-revocations.json` makes revocation idempotent per review.
* Modes: `on_demand` (UI buttons, `/api/review-all`) or `automatic`
  (lifespan loop every 30 s over `Reviewer.pending()`).

---

## 11. HTTP API summary

Public: `GET /`, `GET /approve/{grant_id}`, `GET /health`,
`GET /.well-known/hilait`, `GET /api/auth/mode`, `POST /api/auth/verify`,
`POST /api/agent-enrollment`, `POST /api/agent-enrollment/{id}/status`,
`/static/*`.

Admin (Bearer session): `/api/otp` (+ `setup`, `confirm`, `cancel`,
`disable`), `/api/notifications/ntfy` (+ `test`), `GET /api/state`,
`/api/agent-enrollment/{id}/approve|reject`, `POST /api/profiles`,
`POST /api/profiles/order`, `DELETE /api/profiles/{id}`,
`POST /api/hosts/trust`, `POST|DELETE /api/sessions[/{id}]`,
`POST /api/sessions/{id}/files|copy`, `/api/agents` (+ `{id}/config`,
`{id}/permissions`, `{id}/revoke`, `DELETE {id}`), `/api/authorizations`
(+ `{id}/extend|file-access|revoke`), `GET /api/grants/{id}`,
`POST /api/grants/{id}/{approve|reject|pause|takeover|resume|revoke}`,
`/api/logs` (+ `{id}`, `DELETE {id}`, `{id}/export`),
`GET|PUT /api/activity/settings`, `GET|PUT /api/transfers/settings`,
`GET /api/transfers?path=` (list), `GET|POST|DELETE /api/transfers/file?path=`
(download / raw-body upload, never overwrites / delete; paths relative to the
transfer root), `POST /api/review/settings|models|{id}`,
`POST /api/review-all`, `POST /api/sudo/{id}/decide`.

Agent (Bearer agent token): `POST /agent/{tool}`.

WebSockets: `/ws/events` (state snapshot then events), `/ws/terminal/{id}`
(client → `input` {base64|text}, `resize` {columns, rows},
`screen_response`; server → `output` {base64}, `screen_request`, `closed`).

`GET /api/state` returns `profiles, sessions, agents, tokenRequests, grants,
authorizations, reviewSettings, sudoRequests, otpEnabled` — the UI's main
model.

---

## 12. Front end

* No framework and no bundler for app code: `app.js` is one IIFE using a
  `$()` helper, `api(path, method, body)` (adds the Bearer token, throws
  with server `error`/`detail`), `escaped()` for HTML interpolation, and
  `<dialog>`-based settings panes. Token is kept in `sessionStorage`
  (`hilait-token`).
* CSP in `index.html` is `'self'` only — no inline scripts/styles, no CDNs.
  Keep it that way; all assets are vendored.
* xterm.js injects `<style>` elements (cell dimensions/letter spacing,
  theme and selection colours, scrollbar) that the strict CSP blocks.
  `mirrorInjectedStyles()` in `terminal-entry.js` copies them into
  constructable stylesheets (`document.adoptedStyleSheets`), which CSP does
  not govern. Without it, text drifts from the cell grid (the custom
  `.terminal-caret` overlay looks offset) and selections are invisible. The
  CSP console warnings about those `<style>` elements are expected.
  `build.mjs` also patches xterm's `_addStyle` (truecolor and
  minimum-contrast colours) from `setAttribute('style')`, which the CSP
  blocks, to `element.style.cssText`; the build fails if xterm changes that
  helper.
  `tests/test_terminal_assets.py` guards this.
* `terminal-entry.js` is the only bundled source (xterm 6 + fit, search,
  unicode11, unicode-graphemes). After editing it run `npm ci && npm run
  build` and commit `static/vendor/xterm.js` and fonts.
* `approve.*` is the standalone phone approval page (OTP sign-in, full
  purpose, duration, elevated confirmation).
* Settings → File transfers (`transferSettings` in app.js) browses the
  transfer root with breadcrumbs, uploads/downloads/deletes items, and edits
  the root folder.
* Static URLs are cache-busted with `?v={{VERSION}}`, so **bump the version
  whenever static assets change**. `{{BUILD}}` shows the pip VCS commit
  (`build_id()`), `package`, or `source`.

---

## 13. Development workflow

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[test]'
python -m pytest -q
npm ci && npm run build      # only when terminal-entry.js / xterm deps change
hilait serve --open          # local run on http://127.0.0.1:8765
```

* Tests use temporary data dirs and a loopback asyncssh server
  (`tests/ssh_fixture.py`); `conftest.activate_otp` enables OTP on a runtime.
  Main suites: `test_integration` (SSH, host trust, SFTP, agent scope),
  `test_tiered_access`, `test_transfers`, `test_review`, `test_storage`,
  `test_security_storage`, `test_admin_auth`, `test_agent_enrollment`,
  `test_ntfy`, `test_lan`, `test_mcp`, `test_build_info`,
  `test_terminal_startup`.
* Versioning: bump `version` in `pyproject.toml` **and** `__version__` in
  `src/hilait/__init__.py` together on each user-visible change (history
  shows one bump per feature commit). `package.json`'s version is
  independent and unused at runtime.
* CI runs on every push (Ubuntu/Windows/macOS × 3.11/3.12).

### Known issues at time of writing
* Tests that create directories Hilait will validate must create them with
  `mode=0o700`; otherwise the POSIX privacy check fires first on runners with
  the usual 022 umask (this broke CI after `d008b57`, fixed in the next commit).
* `docs/CREDENTIAL_SECURITY.md` says it describes 0.1.28; the content still
  applies but the version note is stale.

---

## 14. Invariants to preserve when changing code

1. Agents never receive hostnames, usernames, passwords, passphrases, sudo
   passwords, or the admin token. `public_profile(agent=True)` is the only
   profile view agents get.
2. Credentials are sent over SSH only after the host-key fingerprint matches
   a human-trusted value.
3. Each approval opens a fresh SSH session bound to one grant; grants are
   never widened (scope, tier, or machine) after approval.
4. Authorization is per agent × machine × tier and invalidated by credential
   revision changes.
5. Human keystrokes are never stored verbatim; secrets never enter audit
   records deliberately.
6. Every agent-visible operation is audited before/after it runs, and
   operational tools pass through `AgentRuntime.owned(...)`.
7. Secret files are written atomically, mode 0600, and refused if symlinked
   or shared; the data dir must be 0700.
8. Admin tokens never appear in URLs except the one-time `#token=` fragment
   used by `--open` (fragments are not sent to the server).
9. Connection data is encrypted with the OTP-seed key; replacing the seed
   destroys it by design.
10. The browser UI loads nothing from third-party origins.
11. Server-side transfer locations are chosen by Hilait, never by an agent
    or a typed approval field, and are separate per agent × machine × tier
    (so they cannot bridge tiers that `copy` keeps apart).
