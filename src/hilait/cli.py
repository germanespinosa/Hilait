"""hilait serve / hilait mcp entry points."""

from __future__ import annotations

import argparse
import webbrowser

import uvicorn

from .server import create_app
from .tls import ensure_lan_certificate


def main() -> None:
    parser = argparse.ArgumentParser(prog="hilait", description="Hilait SSH workspace and human-controlled agent server")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="start the local web interface")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--open", action="store_true", help="open the browser at the local login screen")
    serve.add_argument("--lan", action="store_true", help="serve HTTPS on the local network using a persistent self-signed certificate")
    mcp = sub.add_parser("mcp", help="run the personal stdio MCP bridge")
    mcp.add_argument("--server", help="full HTTPS URL of the Hilait instance")
    mcp.add_argument("--ca-cert", help="trusted CA certificate for a private HTTPS instance")
    otp = sub.add_parser("otp", help="manage the local web authenticator")
    otp_sub = otp.add_subparsers(dest="otp_command", required=True)
    otp_sub.add_parser("reset", help="remove the OTP seed from this server account (stop Hilait first)")
    passkeys = sub.add_parser("passkeys", help="manage passkey (fingerprint) approval checks")
    passkeys_sub = passkeys.add_subparsers(dest="passkeys_command", required=True)
    passkeys_sub.add_parser("reset", help="forget all passkeys and stop requiring them (stop Hilait first)")
    updater = sub.add_parser("updater", help="set up in-app updates (Linux systemd, run with sudo)")
    updater_sub = updater.add_subparsers(dest="updater_command", required=True)
    install = updater_sub.add_parser("install", help="install the root update helper for the Hilait service")
    install.add_argument("--unit", default="hilait.service", help="systemd unit that runs Hilait")
    install.add_argument("--user", help="service account (default: read from the unit)")
    install.add_argument("--data-dir", help="Hilait data directory (default: read from the unit)")
    install.add_argument("--health-url", help="local health URL (default: built from the unit's --port/--lan)")
    remove = updater_sub.add_parser("uninstall", help="remove the update helper")
    remove.add_argument("--unit", default="hilait.service")
    remove.add_argument("--data-dir")
    args = parser.parse_args()
    if args.command == "updater":
        import os
        import sys
        from .updates import detect, install_updater, uninstall_updater
        if not sys.platform.startswith("linux") or not hasattr(os, "geteuid") or os.geteuid() != 0:
            parser.error("Run this on the Linux server with sudo, e.g. `sudo hilait updater install`.")
        found = detect(args.unit)
        data_dir = args.data_dir or found["data_dir"]
        if args.updater_command == "uninstall":
            uninstall_updater(data_dir)
            print("Hilait updater removed.")
            return
        written, restart = install_updater(unit=args.unit, python=sys.executable, user=args.user or found["user"],
                                           data_dir=data_dir, health_url=args.health_url or found["health_url"],
                                           transfer_dir=found.get("transfer_dir"))
        print("Hilait updater installed:\n  " + "\n  ".join(written))
        if restart:
            print(f"The service may now write its transfer folder. Restart it to apply: sudo systemctl restart {args.unit}")
        print(f"Service {args.unit}, data {data_dir}, health {args.health_url or found['health_url']}.")
        print("Open Settings → Updates in Hilait to install new versions.")
        return
    if args.command == "mcp":
        from .mcp_server import build_mcp
        build_mcp(args.server, args.ca_cert).run(transport="stdio")
        return
    if args.command == "otp":
        from .storage import Store
        store = Store()
        store.discard_connections()
        store.write_secure("admin-otp.json", {})
        print("OTP reset. Saved connections and machine authorizations were deleted. Restart Hilait and sign in with the admin token.")
        return
    if args.command == "passkeys":
        from .passkeys import Passkeys
        from .storage import Audit, Store
        store = Store()
        Passkeys(store, Audit(store)).reset()
        print("Passkeys reset. Approvals no longer require a passkey. Restart Hilait and add a new passkey in Settings → Security.")
        return
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("For network access, use --lan to enable HTTPS. --host is for loopback only.")
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    app = create_app()
    protocol = "https" if args.lan else "http"
    url = f"{protocol}://127.0.0.1:{args.port}"
    uvicorn_options = {}
    if args.lan:
        key_password = app.state.runtime.store.tls_password()
        certificate, private_key, fingerprint, addresses = ensure_lan_certificate(app.state.runtime.store.root, key_password)
        uvicorn_options = {"ssl_certfile": str(certificate), "ssl_keyfile": str(private_key),
                           "ssl_keyfile_password": key_password}
        for address in addresses:
            print(f"Hilait LAN: https://{address}:{args.port}", flush=True)
        if not addresses:
            print(f"Hilait LAN: https://<this-server's-IP>:{args.port}", flush=True)
        print(f"Self-signed certificate SHA-256: {fingerprint}", flush=True)
    else:
        print(f"Hilait: {url}", flush=True)
    otp_enabled = app.state.runtime.auth.enabled()
    if otp_enabled:
        print("OTP enabled: open Hilait and enter your authenticator code.", flush=True)
    else:
        print(f"Admin token: {app.state.runtime.store.admin_token}", flush=True)
    if args.open:
        webbrowser.open(url + ("/" if otp_enabled else "/#token=" + app.state.runtime.store.admin_token))
    import logging
    logging.getLogger("httpx").setLevel(logging.WARNING)  # it logs every request at INFO
    uvicorn.run(app, host="0.0.0.0" if args.lan else args.host, port=args.port,
                log_level="info", timeout_graceful_shutdown=30, **uvicorn_options)
