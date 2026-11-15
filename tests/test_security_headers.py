import httpx

from hilait.security import MAX_BODY_BYTES
from hilait.server import create_app


async def test_security_headers_and_body_limits(tmp_path, activate_otp):
    app = create_app(tmp_path / "data")
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        for path in ("/", "/approve/00000000-0000-0000-0000-000000000000", "/static/app.js", "/health"):
            response = await client.get(path)
            assert response.headers["x-frame-options"] == "DENY", path
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["referrer-policy"] == "no-referrer"
            assert "strict-transport-security" not in response.headers
        assert "frame-ancestors 'none'" in (await client.get("/")).headers["content-security-policy"]
        proxied = await client.get("/health", headers={"x-forwarded-proto": "https"})
        assert proxied.headers["strict-transport-security"] == "max-age=31536000"
        assert "connect-src 'self';" in (await client.get("/")).text

        huge = b'{"name":"x","reason":"' + b"a" * (MAX_BODY_BYTES + 10) + b'"}'
        for path in ("/api/agent-enrollment", "/api/auth/verify", "/api/auth/passkey/verify"):
            response = await client.post(path, content=huge, headers={"content-type": "application/json"})
            assert response.status_code == 413, path
            assert response.headers["x-frame-options"] == "DENY"

        async def chunked():
            for _ in range(5):
                yield b"x" * (MAX_BODY_BYTES // 2)
        response = await client.post("/api/auth/verify", content=chunked(), headers={"content-type": "application/json"})
        assert response.status_code == 413
        # Normal JSON bodies still work after the middleware replays them.
        assert (await client.post("/api/auth/verify", json={"code": "123"})).status_code == 400
        # Administrator transfer uploads stream past the JSON limit.
        runtime.transfers.update_settings(str(tmp_path / "transfers"))
        (tmp_path / "transfers" / "a").mkdir(mode=0o700)
        big = await client.post("/api/transfers/file", params={"path": "a/big.bin"}, headers=headers,
                                content=b"y" * (MAX_BODY_BYTES + 1024))
        assert big.status_code == 200, big.text
        assert big.json()["size"] == MAX_BODY_BYTES + 1024
