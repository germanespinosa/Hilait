# Hilait

[![Test and package](https://github.com/germanespinosa/Hilait/actions/workflows/ci.yml/badge.svg)](https://github.com/germanespinosa/Hilait/actions/workflows/ci.yml)

**A human-in-the-loop SSH workspace you can run with Python.** Hilait serves a local web interface for interactive terminals, remote files, and controlled access for AI agents. It runs on Windows, Linux, and macOS. The server owns SSH credentials; agents receive a named, limited MCP configuration and must state their purpose before requesting a machine.

This is the Python and browser edition of [HilaitWin](https://github.com/germanespinosa/HilaitWin). It keeps the same connection, agent, audit, and review concepts while replacing Windows-only windows and Explorer shell integration with a browser workspace.

## Install and start

Python 3.11 or newer is required. A virtual environment is recommended.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install .
hilait serve --open
```

To install straight from GitHub **without Git installed**:

```bash
python -m pip install 'https://github.com/germanespinosa/Hilait/archive/refs/heads/main.zip'
hilait serve --open
```

The `git+https://...` form also works, but it requires the `git` executable on the server:

```bash
python -m pip install git+https://github.com/germanespinosa/Hilait.git
hilait serve --open
```

The server binds to `127.0.0.1:8765` by default. Before OTP is configured, it prints an admin token and opens the browser when `--open` is used. If the browser cannot be launched, visit `http://127.0.0.1:8765` and paste the printed token. **Set up an authenticator before creating saved machine connections.** With OTP enabled, `--open` goes directly to the authenticator screen and the server no longer prints the admin token.

```bash
hilait serve --port 8766
```

To open Hilait directly from another computer on a trusted network, stop the running server and start its HTTPS LAN mode:

```bash
hilait serve --lan
```

Hilait prints one or more `https://<server-ip>:8765` addresses and a certificate fingerprint. Open the matching address from the other computer and enter the admin token if OTP is not configured, or the authenticator code if it is. The first visit shows a browser warning because Hilait generates its own self-signed certificate; compare the certificate's SHA-256 fingerprint with the server output before accepting it. The certificate and private key stay in Hilait's per-user data directory so the fingerprint remains stable across restarts. Allow TCP port 8765 through the server firewall if it is blocked. `--lan` listens on all network interfaces, so use it only on a network where access is restricted to people you intend to serve. To avoid a LAN listener, keep the default mode and use an SSH tunnel instead.

### Authenticator and saved connections

Open **Settings → Authenticator → Generate OTP seed**, scan the QR code with Google Authenticator or another TOTP app, then enter its six-digit code to activate it. You can also enter the displayed seed manually. Until activation, the admin token opens the workspace as before. After activation, Hilait asks only for the six-digit code; the admin token cannot use the web API or terminal WebSockets. A verified browser session lasts up to 12 hours and ends when Hilait restarts. The seed is encrypted in Hilait's data directory, and the QR code is generated locally. OTP is the sole web login factor while enabled, so keep the authenticator device and server account secure.

The active OTP seed derives the encryption key for saved machine profiles, trusted host fingerprints, and machine authorizations. On first setup, existing unencrypted connection data from older versions is migrated into this encrypted store. **Replacing the OTP key, turning OTP off, or running `hilait otp reset` permanently deletes that saved connection data.** The UI warns before replacement or disabling; active SSH sessions must be disconnected first. If the authenticator is lost, stop Hilait and run `hilait otp reset` as the same server account, then restart and sign in with the admin token to set up a new authenticator. Anyone who can run that command as the server account can also read Hilait's local secrets, so protect that account. Agent tokens and their access workflow are separate from the human OTP login.

### Phone notifications with ntfy

In **Settings → Notifications**, enter your ntfy server URL, a private topic, an optional ntfy access token, and the HTTPS URL by which your phone reaches Hilait. Save the settings, then use **Send test**. The ntfy phone app must subscribe to that topic; protect it with ntfy's access controls. The access token is encrypted in Hilait's local data and is never returned to the browser after saving.

When an agent requests access without a matching authorization, Hilait sends the agent name, machine name, file scope, and a short purpose preview. **Review and approve** and **Review and deny** open a mobile-friendly Hilait page for that specific request. Sign in with the authenticator code when OTP is enabled, read the complete purpose, choose an approval duration, then confirm. The notification itself never contains the Hilait admin token or a credential that can approve access. Requests expire after ten minutes; stale links cannot approve or deny them. If ntfy is unreachable, the request remains pending in Hilait and delivery failure is recorded in the audit log.

When an agent asks for a token, Hilait also sends a notification with the agent's name and reason. **Review in Agent Access** opens the workspace on Settings → Agent Access, where you choose its machines and approve it. Token requests expire after ten minutes. Your phone needs a trusted LAN or VPN path to Hilait; ntfy does not need inbound access to Hilait.

The package includes its terminal JavaScript and CSS. Node.js is needed only when rebuilding those assets from source.

### Fingerprint approvals with passkeys

Hilait can require a passkey, such as your phone's or computer's fingerprint, face unlock, or device PIN, before it grants or widens agent access. Open **Settings → Passkeys**:

1. Enter the HTTPS address you open Hilait at, such as `https://hilait.example.com` (include the port if you use one), and save with a current authenticator code. Browsers allow passkeys only at a domain name with a trusted certificate, not at an IP address or behind a certificate warning, so use a reverse proxy or another trusted HTTPS front end for that name.
2. Open Hilait at that address on each device you will approve from, then choose **Add passkey on this device** and confirm with your fingerprint. Passkeys saved to Google Password Manager or iCloud Keychain also work on your other signed-in devices.
3. Choose when to require one: **Elevated access and sudo approvals**, or **Every approval**.

Once a passkey is registered, the sign-in screens in the workspace and on the phone approval page also offer **Sign in with passkey** as an alternative to the authenticator code (only at the configured address). Passkey sign-in shares the code's rate limit and creates the same 12-hour session.

When required, approving a request (in the workspace or on the phone page), approving sudo, creating or extending a standing authorization, widening its file access, or approving an agent token prompts for the passkey. Each check is tied to that one action and request, works once, and expires after two minutes. Rejecting, pausing, revoking, and taking over never ask. Changing settings or removing a passkey needs an authenticator code. If you lose every passkey, stop Hilait and run `hilait passkeys reset`; it forgets all passkeys and turns the requirement off. Set the ntfy **Hilait URL** to the same address so notification links open where your passkey works.

## Use the workspace

The workspace adapts to the screen: three columns on desktop, connections and sessions in one column on tablets, and on phones a connections list with a full-screen terminal (use the back arrow to return). It is tested in Chromium, Firefox, and WebKit (Safari) in light and dark mode.

Create a saved machine with a display name, host, port, and SSH username. Under **Authentication & access**, choose **Username and password** or **Username and private key** for each configured SSH account. A private key path refers to a file readable by the Hilait server account; the browser does not upload the key. Saved passwords and key passphrases are encrypted locally. Switching methods clears the previously saved login secret. Hilait verifies the server's SHA-256 host-key fingerprint *before* sending SSH credentials. Compare a new or changed fingerprint with a trusted source, then explicitly trust it. You can keep multiple independent SSH terminals to the same machine; each agent purpose gets its own session.

The left column holds saved machines. Drag one between its neighbors to save a new order. Selecting a machine shows only its active sessions, newest first. A new session selects its machine and terminal automatically; closed sessions disappear. Double-click a machine to connect, and disconnect from the terminal header or a session's context menu. Disconnecting warns that a remote foreground command or transfer may be interrupted.

The workspace starts in your device's light or dark appearance. Use the color-mode button in the sidebar for a quick switch, or choose **Light** or **Dark** in **Settings → Appearance**. The choice is saved in your browser and also applies to the phone approval page. Appearance settings offer terminal font and size controls with a live preview; the terminal background stays black in either color mode.

The terminal uses a black background in every appearance mode, bundled xterm.js, and a configurable monospaced font (JetBrains Mono by default) with Unicode, ANSI color, alternate screen programs, scrollback, resizing, selection, copy/paste, search, and a rendered screen snapshot. Its layout adapts to narrow browsers without squeezing the terminal into a side column. Ctrl+C copies a selection and otherwise reaches the shell. Ctrl+V pastes; multiline pastes ask for confirmation. Right-click opens Copy and Paste. Ctrl+F searches scrollback, Ctrl+U toggles Unicode width behavior, and Ctrl+plus/minus changes the terminal font size.

**Files** opens a remote SFTP pane beside the selected terminal. Browse directories, create folders, upload and download through the browser, and rename or delete from the context menu. The SFTP API additionally supports paged listings, stat, bounded reads and writes, POSIX chmod, symlinks, and remote-to-remote or local-folder copies. Copy destinations must be new; recursive copies refuse symbolic links and do not overwrite. Each active session has its own SFTP channel.

Windows SSH machines can launch PowerShell 7 or Windows PowerShell 5.1 in the PTY. SFTP paths on those machines accept `C:\Users\name` or `/C:/Users/name`. POSIX chmod, symlinks, and managed sudo are not offered for Windows SSH machines.

## Give an agent access

### Hosted MCP endpoint (recommended)

Hilait serves MCP itself at `https://<your Hilait address>/mcp` (Streamable HTTP), so nothing needs installing on the agent's computer. Open **Settings → Agent Access → Create agent access**, name the agent, and choose **Connect**. Copy the Claude Code command and run it once where Claude Code runs:

```bash
claude mcp add --scope user --transport http hilait https://hilait.example.com/mcp --header "Authorization: Bearer <agent token>"
claude mcp list   # hilait … ✓ Connected
```

The same dialog offers JSON for other MCP clients that support Streamable HTTP. Every request must carry the agent token; a missing, wrong, or revoked token gets HTTP 401. The token works like a password: anyone holding it can *request* access as that agent (each request still needs your approval). Revoke it in Agent Access at any time. The hosted endpoint offers the ten machine tools below; agents cannot self-enroll through it.

### Local bridge with self-enrollment

Alternatively, an agent can run the `hilait mcp` bridge on its own computer and be given **only your full HTTPS Hilait URL**. Install the `hilait` package on the agent's computer and add this MCP server, replacing the example URL with your instance (in Claude Code: `claude mcp add --scope user hilait -- hilait mcp --server https://hilait.example.com`):

```json
{
  "mcpServers": {
    "hilait": {
      "command": "hilait",
      "args": ["mcp", "--server", "https://hilait.example.com"]
    }
  }
}
```

The agent calls `request_agent_token(name, reason)`, then `agent_token_status()` while you review the request under **Settings → Agent Access**. You must have OTP configured and be signed in with OTP to approve it. Choose the machines the new agent may see; none are selected by default. Approval creates its identity and the MCP bridge privately saves the token on the agent's computer. The token and its private claim secret never need to be pasted into the agent's prompt or MCP configuration. Rejection or a ten-minute timeout grants nothing. The bridge keeps the token for later runs; revoke it at any time in Agent Access. For a self-signed HTTPS instance, trust its certificate and set `--ca-cert /path/to/certificate.pem` in the MCP args. The server also exposes `POST /api/agent-enrollment` and `POST /api/agent-enrollment/{id}/status` for non-MCP clients; the status call requires the private claim returned when the request was created.

The MCP process also exposes the two enrollment tools above and ten machine tools: `connections`, `request_access`, `access_status`, `release_access`, `terminal_write`, `terminal_read`, `terminal_screen`, `files`, `copy`, and `request_sudo`. The `connections` result contains only permitted display names and IDs, without usernames or hostnames. Set **Allowed connections** per agent or choose an agent restriction when editing a machine. New machines allow all registered agents by default; permission to *request* a machine is not approval to *use* it.

An agent requests one machine, a detailed purpose of 80–8000 characters, and the file scope it needs: `None`, `Remote`, or `LocalTransfers`. The human reviews the agent, machine, purpose, and requested file scope. Approving opens a new SSH session; rejecting ends the request.

`Remote` enables the SFTP tools on the remote machine. `LocalTransfers` adds `copy` uploads and downloads between that machine and a **transfer folder on the Hilait server**, never the agent's own computer. Hilait creates one folder per agent, machine, and access tier under its transfer root, so nobody types a path when approving; the agent sees its folder as `localFolder` in `access_status` and addresses files in it by relative path. Open **Settings → File transfers** to browse those folders, upload files for an agent to use, download what it collected, or delete items. The transfer root defaults to a sibling of Hilait's data directory (for example `~/.local/share/Hilait-transfers`, or `/var/lib/hilait-transfers` for the systemd service), can be set with `HILAIT_TRANSFER_DIR`, and can be changed in that pane. It must be private to the Hilait account and outside the data and activity folders. Transfers keep file contents off the MCP connection, which suits large files and data that should not pass through the agent's model. File access cannot be silently added to an existing grant. A timed or permanent authorization covers only that agent on that specific machine with the approved file scope or less. Different machines always need separate authorization. **Settings → Authorizations** lists active authorizations and lets you create, extend, or revoke them; expired and revoked records remain in the audit history. The **Automatic revocation settings** button opens the score thresholds under **Settings → Activity review**. Permanent authorization remains active until revoked. Pending requests expire after ten minutes.

### Normal and elevated SSH access

Existing saved machines stay in **Legacy** mode, with their current SSH account and authorizations. For a Unix machine, edit its connection and explicitly select **Tiered** mode to use separate Normal and Elevated SSH accounts. The Normal account must be an OS account that cannot use `sudo`, `su`, privileged groups, writable service files, or another path to administrative access; Hilait requires you to confirm this but cannot enforce the host's account policy. Configure a different Elevated username and its SSH credentials if agents need privileged work. Tiered mode is not currently offered for Windows SSH machines.

Normal and Elevated eligibility are set separately for each agent and machine under **Allowed connections**. Elevated eligibility starts denied. An eligible agent calls `request_access` with `privilege` set to `normal` or `elevated`; the connection listing shows the available tiers. Each request shows its tier, purpose, and file scope. Elevated approval requires an explicit confirmation and displays a stronger warning, including on the phone approval page. Timed and permanent authorizations are also tier-specific: authorizing Normal does not authorize Elevated. Elevation opens a new SSH session as the separate Elevated account; an existing Normal session is never promoted. Hilait refuses managed `request_sudo` in Normal sessions. The host account restriction is essential because ordinary terminal commands can still invoke `sudo` or other escalation tools directly if the host permits them.

In **Settings → Activity review**, configure independent score thresholds for Normal/Legacy and Elevated sessions. A matching score revokes that tier's agent grants and standing authorization on the machine and closes live sessions. An optional safety setting also revokes the other tier when a safety score triggers. Changing a machine's SSH credentials or tier revokes affected standing authorizations; close affected live sessions before making that change. Review settings apply to completed reviews; automatic review must be enabled for ongoing scoring.

The owner can pause, take over, resume, or revoke agent control. A paused or revoked agent cannot send more input or file operations through Hilait. A remote command already running is not undone by revocation; interrupt it in the visible terminal if necessary. Idle agent sessions close after the machine's inactivity timeout (10 minutes by default, 0 disables it). Agents should call `release_access(closeConnection=true)` as soon as their stated purpose is complete.

For Unix sudo, agents use `request_sudo(access, command, reason)`. The browser selects the affected session and shows a private human approval prompt. The agent never receives the password. Each machine can ask every time, once per connection, once per authorization period, or automatically use a saved sudo password. The managed command runs on a separate noninteractive SSH channel and does not inherit the visible terminal's working directory.

## Audit and activity review

Hilait encrypts audit records and links them with a SHA-256 hash chain. Each record is stored in its own numbered file under `activity-records/`, with 1,000 files per subfolder. Existing `activity.audit` files are migrated on startup; the old file is removed only after the new records pass validation. Records include access decisions, terminal bytes, file operations, transfer outcomes, and managed sudo outcomes. Human terminal keystrokes are redacted because they may contain passwords; SSH login and sudo passwords are never deliberately placed in audit records. The hash chain detects local record edits or reordering, not deletion by someone who controls the server account. Ended session logs can be deleted from the Logs window. Export a session as readable JSON with instructions for another AI reviewer to assess it.

**Settings → Activity storage** lets an administrator move the encrypted record folder to an absolute path on the Hilait server and choose how long to retain activity. The destination must be a new folder or an empty private folder owned by the service account. Hilait copies and verifies the records before switching, while the encryption key and record index remain in the main data directory. Retention defaults to forever. A finite period deletes complete sessions only when their last activity is older than the period; active sessions are protected. Old non-session events and review results for deleted sessions are also removed. Cleanup runs when settings are saved and hourly afterward.

In **Settings → Activity review**, choose **Local / Ollama**, **OpenAI**, **Anthropic**, or **Grok (xAI)**, enter an API key when required, connect to list available models, and select one. The default endpoints are `http://localhost:11434/v1`, `https://api.openai.com/v1`, `https://api.anthropic.com/v1`, and `https://api.x.ai/v1`; hosted providers require HTTPS. Keys are encrypted locally and are never returned to the browser after saving. **On demand** reviews start from session-log context menus or **Review all pending**; **Automatic** reviews run as activity is recorded.

Choose **Light** to send the stated reason, agent terminal inputs, sudo requests, file-operation instructions, and short preceding menu or prompt excerpts. These excerpts help distinguish a menu selection from a shell command; full command results are not sent. It scores safety and purpose alignment, leaving correctness unscored. Choose **Deep** to also send full terminal output and file-operation results, including recorded file content, so the model can score correctness from errors, retries, and verification. Each result includes 0–10 scores, brief rationales, a short summary, and links to cited or flagged activity. Logged content is explicitly treated as untrusted evidence. A 0–4 score prompts a concise concern summary. Switching depth or model makes prior sessions eligible for review again. Scores are advisory by default; configured revocation thresholds can act on them.

Set a separate **Score alert** threshold for safety, purpose alignment, and correctness (or leave an axis Off). A newly completed review at or below a threshold sends an ntfy notification with the scores and short summary. Configure the ntfy server, topic, and phone-accessible Hilait URL in **Settings → Notifications**. Review alerts are independent of the access-request notification toggle; light reviews cannot trigger correctness alerts. Review progress appears in the status bar. Sending a review to a hosted provider transfers the evidence selected by the review depth to that provider.

Set separate **Automatic access revocation** thresholds for safety, purpose alignment, and correctness. A review at or below any enabled threshold revokes the agent's current access and standing authorization on that machine and closes the active SSH session. The thresholds apply to both automatic and on-demand reviews; choose Automatic frequency for continuing checks. Correctness requires Deep review. Reviews that fail to produce scores cannot trigger revocation. If the model provider rejects the API key or cannot find the model, automatic reviews pause until you save the review settings again, and the reason appears at the top of **Settings → Activity review**. Rate limits and outages back off from five minutes up to six hours, a session that fails on its own is retried later without holding up others, and at most five automatic reviews start every 30 seconds. The agent receives a prominent warning that activity is recorded for review and that obfuscation or suspicious activity can lead to revocation.

## Storage and trust

Hilait encrypts saved SSH and sudo secrets, connection records, agent tokens, the admin recovery token, the OTP seed, audit activity, and the built-in HTTPS private key. The hardened Linux service runs under a dedicated non-login account and receives its master key through systemd credentials rather than keeping it beside the encrypted data. See [How Hilait protects credentials](docs/CREDENTIAL_SECURITY.md) for the exact keys, file permissions, migration steps, and runtime limits. In particular, root on the live Hilait host can still access the service's secrets; do not grant root or sudo to people you do not trust with them.

The browser workspace and API are intended for a trusted local user or a restricted LAN over Hilait's HTTPS mode. An authenticated SSH tunnel is another remote-access option. The server does not expose SSH passwords to agents. Purpose text is an audit commitment, not a semantic sandbox: an approved SSH account retains its normal OS privileges. Use the remote account's permissions to bound its possible effects.

## Develop and test

```bash
python -m pip install -e '.[test]'
python -m pytest
npm ci
npm run build
```

The test suite uses an isolated loopback SSH fixture and temporary data directories. It does not need real server credentials. The Python source lives in `src/hilait`; the browser UI and bundled terminal live in `src/hilait/static`. See [the codebase reference](docs/CODEBASE.md) for the architecture, stored files, APIs, and security invariants.
GitHub Actions runs the same tests and wheel build on Windows, Linux, and macOS with Python 3.11 and 3.12.

## License

Hilait's Python and web application code is MIT licensed. The bundled xterm.js assets retain their upstream MIT licenses; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
