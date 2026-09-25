"""hilait serve / hilait mcp entry points."""

from __future__ import annotations

import argparse
import webbrowser

import uvicorn

from .server import create_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="hilait", description="Hilait SSH workspace and human-controlled agent server")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="start the local web interface")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--open", action="store_true", help="open the browser with the local admin token")
    sub.add_parser("mcp", help="run the personal stdio MCP bridge")
    args = parser.parse_args()
    if args.command == "mcp":
        from .mcp_server import run
        run()
        return
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("Hilait binds only to loopback. Use SSH port forwarding for access from another machine.")
    app = create_app()
    url = f"http://127.0.0.1:{args.port}"
    print(f"Hilait: {url}", flush=True)
    print(f"Admin token: {app.state.runtime.store.admin_token}", flush=True)
    if args.open:
        webbrowser.open(url + "/#token=" + app.state.runtime.store.admin_token)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")

