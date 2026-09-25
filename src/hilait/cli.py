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
    serve.add_argument("--open", action="store_true", help="open the browser with the local admin token")
    serve.add_argument("--lan", action="store_true", help="serve HTTPS on the local network using a persistent self-signed certificate")
    sub.add_parser("mcp", help="run the personal stdio MCP bridge")
    otp = sub.add_parser("otp", help="manage the local web authenticator")
    otp_sub = otp.add_subparsers(dest="otp_command", required=True)
    otp_sub.add_parser("reset", help="remove the OTP seed from this server account (stop Hilait first)")
    args = parser.parse_args()
    if args.command == "mcp":
        from .mcp_server import run
        run()
        return
    if args.command == "otp":
        from .storage import Store
        Store().write_secure("admin-otp.json", {})
        print("OTP reset. Restart Hilait and sign in with the admin token.")
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
        certificate, private_key, fingerprint, addresses = ensure_lan_certificate(app.state.runtime.store.root)
        uvicorn_options = {"ssl_certfile": str(certificate), "ssl_keyfile": str(private_key)}
        for address in addresses:
            print(f"Hilait LAN: https://{address}:{args.port}", flush=True)
        if not addresses:
            print(f"Hilait LAN: https://<this-server's-IP>:{args.port}", flush=True)
        print(f"Self-signed certificate SHA-256: {fingerprint}", flush=True)
    else:
        print(f"Hilait: {url}", flush=True)
    print(f"Admin token: {app.state.runtime.store.admin_token}", flush=True)
    if args.open:
        webbrowser.open(url + "/#token=" + app.state.runtime.store.admin_token)
    uvicorn.run(app, host="0.0.0.0" if args.lan else args.host, port=args.port,
                log_level="info", **uvicorn_options)
