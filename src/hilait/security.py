"""HTTP hardening applied to every response: security headers and body limits."""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_BODY_BYTES = 2 * 1024 * 1024  # JSON APIs; the largest legitimate body is a ~350 KB file chunk
STREAMED_UPLOADS = ("/api/transfers/file",)  # administrator-only, written to disk as it streams

SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"frame-ancestors 'none'"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
                            b"publickey-credentials-get=(self), publickey-credentials-create=(self)"),
]


class SecurityMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        https = scope.get("scheme") == "https" or headers.get(b"x-forwarded-proto", b"").lower() == b"https"
        limited = not scope["path"].startswith(STREAMED_UPLOADS)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {name.lower() for name, _ in message.get("headers", [])}
                extra = [(name, value) for name, value in SECURITY_HEADERS if name not in existing]
                if https:
                    extra.append((b"strict-transport-security", b"max-age=31536000"))
                message["headers"] = list(message.get("headers", [])) + extra
            await send(message)

        if limited:
            try:
                declared = int(headers.get(b"content-length", b"0") or 0)
            except ValueError:
                declared = MAX_BODY_BYTES + 1
            if declared > MAX_BODY_BYTES:
                await _too_large(send_with_headers)
                return
            # Read the bounded body first, then replay it to the application.
            chunks, received = [], 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body = message.get("body", b"")
                received += len(body)
                if received > MAX_BODY_BYTES:
                    await _too_large(send_with_headers)
                    return
                chunks.append(body)
                if not message.get("more_body", False):
                    break
            replayed = False

            async def replay() -> Message:
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
                return await receive()

            await self.app(scope, replay, send_with_headers)
            return
        await self.app(scope, receive, send_with_headers)


async def _too_large(send) -> None:
    body = b'{"error":"Request is too large."}'
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})
