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

The server binds to `127.0.0.1:8765` by default. Before OTP is configured, it prints an admin token and opens the browser when `--open` is used. If the browser cannot be launched, visit `http://127.0.0.1:8765` and paste the printed token. With OTP enabled, `--open` goes directly to the authenticator screen and the server no longer prints the admin token.

```bash
hilait serve --port 8766
```

To open Hilait directly from another computer on a trusted network, stop the running server and start its HTTPS LAN mode:

```bash
hilait serve --lan
```

Hilait prints one or more `https://<server-ip>:8765` addresses and a certificate fingerprint. Open the matching address from the other computer and enter the admin token if OTP is not configured, or the authenticator code if it is. The first visit shows a browser warning because Hilait generates its own self-signed certificate; compare the certificate's SHA-256 fingerprint with the server output before accepting it. The certificate and private key stay in Hilait's per-user data directory so the fingerprint remains stable across restarts. Allow TCP port 8765 through the server firewall if it is blocked. `--lan` listens on all network interfaces, so use it only on a network where access is restricted to people you intend to serve. To avoid a LAN listener, keep the default mode and use an SSH tunnel instead.

### Optional authenticator code

Open **Settings → Authenticator → Generate OTP seed**, scan the QR code with Google Authenticator or another TOTP app, then enter its six-digit code to activate it. You can also enter the displayed seed manually. Until activation, the admin token opens the workspace as before. After activation, Hilait asks only for the six-digit code; the admin token cannot use the web API or terminal WebSockets. A verified browser session lasts up to 12 hours and ends when Hilait restarts. The seed is encrypted in Hilait's data directory, and the QR code is generated locally. OTP is the sole web login factor while enabled, so keep the authenticator device and server account secure.

The OTP tab can replace or disable the authenticator with a current code. If the authenticator is lost, stop Hilait and run `hilait otp reset` as the same server account, then restart and sign in with the admin token. Anyone who can run that command as the server account can also read Hilait's local secrets, so protect that account. Agent tokens and their access workflow are separate from the human OTP login.

### Phone notifications with ntfy

In **Settings → Notifications**, enter your ntfy server URL, a private topic, an optional ntfy access token, and the HTTPS URL by which your phone reaches Hilait. Save the settings, then use **Send test**. The ntfy phone app must subscribe to that topic; protect it with ntfy's access controls. The access token is encrypted in Hilait's local data and is never returned to the browser after saving.

When an agent requests access without a matching authorization, Hilait sends the agent name, machine name, file scope, and a short purpose preview. **Review and approve** and **Review and deny** open a mobile-friendly Hilait page for that specific request. Sign in with the authenticator code when OTP is enabled, read the complete purpose, choose an approval duration and any required local transfer folder, then confirm. The notification itself never contains the Hilait admin token or a credential that can approve access. Requests expire after ten minutes; stale links cannot approve or deny them. If ntfy is unreachable, the request remains pending in Hilait and delivery failure is recorded in the audit log. Your phone needs a trusted LAN or VPN path to Hilait; ntfy does not need inbound access to Hilait.

The package includes its terminal JavaScript and CSS. Node.js is needed only when rebuilding those assets from source.

## Use the workspace

Create a saved machine with a display name, host, port, username, and optional SSH password or private-key path. A saved password or passphrase is encrypted locally. Hilait verifies the server's SHA-256 host-key fingerprint *before* sending SSH credentials. Compare a new or changed fingerprint with a trusted source, then explicitly trust it. You can keep multiple independent SSH terminals to the same machine; each agent purpose gets its own session.

The left column holds saved machines. Drag one between its neighbors to save a new order. Selecting a machine shows only its active sessions, newest first. A new session selects its machine and terminal automatically; closed sessions disappear. Double-click a machine to connect, and disconnect from the terminal header or a session's context menu. Disconnecting warns that a remote foreground command or transfer may be interrupted.

The workspace follows your device's light or dark appearance by default. Use the color-mode button in the sidebar for a quick switch, or choose **System**, **Light**, or **Dark** in **Settings → Appearance**. The preference is saved in your browser and also applies to the terminal and phone approval page.

The terminal uses bundled xterm.js and JetBrains Mono with Unicode, ANSI color, alternate screen programs, scrollback, resizing, selection, copy/paste, search, and a rendered screen snapshot. Its layout adapts to narrow browsers without squeezing the terminal into a side column. Ctrl+C copies a selection and otherwise reaches the shell. Ctrl+V pastes; multiline pastes ask for confirmation. Right-click opens Copy and Paste. Ctrl+F searches scrollback, Ctrl+U toggles Unicode width behavior, and Ctrl+plus/minus changes the terminal font size.

**Files** opens a remote SFTP pane beside the selected terminal. Browse directories, create folders, upload and download through the browser, and rename or delete from the context menu. The SFTP API additionally supports paged listings, stat, bounded reads and writes, POSIX chmod, symlinks, and remote-to-remote or local-folder copies. Copy destinations must be new; recursive copies refuse symbolic links and do not overwrite. Each active session has its own SFTP channel.

Windows SSH machines can launch PowerShell 7 or Windows PowerShell 5.1 in the PTY. SFTP paths on those machines accept `C:\Users\name` or `/C:/Users/name`. POSIX chmod, symlinks, and managed sudo are not offered for Windows SSH machines.

## Give an agent access

Open **Settings → Agents → Create agent**. Hilait creates a named identity and a unique secret token. Copy its MCP configuration into the agent's client. It runs the installed `hilait mcp` command and connects to the local server. Keep the server running while agents work.

The MCP process exposes ten tools: `connections`, `request_access`, `access_status`, `release_access`, `terminal_write`, `terminal_read`, `terminal_screen`, `files`, `copy`, and `request_sudo`. The `connections` result contains only permitted display names and IDs, without usernames or hostnames. Set **Allowed connections** per agent or choose an agent restriction when editing a machine. New machines allow all registered agents by default; permission to *request* a machine is not approval to *use* it.

An agent requests one machine, a detailed purpose of 80–8000 characters, and the file scope it needs: `None`, `Remote`, or `LocalTransfers`. The human reviews the agent, machine, purpose, and requested file scope. Approving opens a new SSH session; rejecting ends the request. File access cannot be silently added to an existing grant. A timed authorization covers only that agent on that specific machine with the approved file scope or less. Different machines always need separate authorization. Settings can create, extend, and revoke per-agent, per-machine authorizations. Pending requests expire after ten minutes.

The owner can pause, take over, resume, or revoke agent control. A paused or revoked agent cannot send more input or file operations through Hilait. A remote command already running is not undone by revocation; interrupt it in the visible terminal if necessary. Idle agent sessions close after the machine's inactivity timeout (10 minutes by default, 0 disables it). Agents should call `release_access(closeConnection=true)` as soon as their stated purpose is complete.

For Unix sudo, agents use `request_sudo(access, command, reason)`. The browser selects the affected session and shows a private human approval prompt. The agent never receives the password. Each machine can ask every time, once per connection, once per authorization period, or automatically use a saved sudo password. The managed command runs on a separate noninteractive SSH channel and does not inherit the visible terminal's working directory.

## Audit and activity review

Hilait encrypts audit records and links them with a SHA-256 hash chain. Records include access decisions, terminal bytes, file operations, transfer outcomes, and managed sudo outcomes. Human terminal keystrokes are redacted because they may contain passwords; SSH login and sudo passwords are never deliberately placed in audit records. The hash chain detects local record edits or reordering, not deletion by someone who controls the server account. Ended session logs can be deleted from the Logs window. Export a session as readable JSON with instructions for another AI reviewer to assess it.

In **Settings → Activity review**, enter an OpenAI-compatible endpoint such as `http://localhost:11434/v1`, connect to list available models, select one, and choose **Automatic** or **On demand**. The selected model scores safety, purpose alignment, and correctness from 0 to 10, writes short rationales, and cites specific event numbers for wrong, unnecessary, problematic, or dangerous actions. The reviewer is explicitly told to treat logged content as untrusted evidence. Results appear on each session log; pending logs can be reviewed from their context menu or with **Review all pending**. Progress appears in the status bar. Scores are advisory and never change access permissions.

## Storage and trust

Hilait stores profiles, known host fingerprints, agent identities, authorizations, review settings, and encrypted activity in the per-user application data directory selected by `platformdirs`. `master.key` encrypts saved secrets, OTP seed, and audit records with Fernet; on Unix its file and directory are created with owner-only permissions. Protect the account and that file together: copying the key with the data permits decryption. The admin token is in `admin.token`; keep it private for use if OTP is reset. While OTP is enabled, it is not accepted for web access. Agent tokens are distinct and grant access only through an approved, named identity.

The browser workspace and API are intended for a trusted local user or a restricted LAN over Hilait's HTTPS mode. An authenticated SSH tunnel is another remote-access option. The server does not expose SSH passwords to agents. Purpose text is an audit commitment, not a semantic sandbox: an approved SSH account retains its normal OS privileges. Use the remote account's permissions to bound its possible effects.

## Develop and test

```bash
python -m pip install -e '.[test]'
python -m pytest
npm ci
npm run build
```

The test suite uses an isolated loopback SSH fixture and temporary data directories. It does not need real server credentials. The Python source lives in `src/hilait`; the browser UI and bundled terminal live in `src/hilait/static`.
GitHub Actions runs the same tests and wheel build on Windows, Linux, and macOS with Python 3.11 and 3.12.

## License

Hilait's Python and web application code is MIT licensed. The bundled xterm.js assets retain their upstream MIT licenses; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
