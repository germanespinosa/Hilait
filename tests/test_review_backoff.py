import asyncio
import time

import httpx
import pytest

import hilait.review as review_module
from hilait.review import BACKOFF_FIRST, ReviewProviderError
from hilait.server import create_app


def _seed_sessions(runtime, count):
    for index in range(count):
        context = {"grant": f"grant-{index}", "agentId": "agent-1", "agent": "Agent", "profile": "m1",
                   "connection": "Machine", "purpose": "Check the service status and report back to the user."}
        runtime.audit.write("access_requested", context, {"purpose": context["purpose"]})
        runtime.audit.write("terminal_input_sent", context, {"text": "systemctl status nginx\n"})


@pytest.fixture
def provider(monkeypatch):
    real_client = httpx.AsyncClient
    calls = {"count": 0, "status": 401, "client": real_client}

    def handler(request):
        calls["count"] += 1
        return httpx.Response(calls["status"], json={"error": {"message": "Incorrect API key"}})

    monkeypatch.setattr(review_module.httpx, "AsyncClient",
                        lambda *args, **kwargs: real_client(transport=httpx.MockTransport(handler),
                                                            **{k: v for k, v in kwargs.items() if k != "transport"}))
    return calls


async def test_rejected_key_pauses_reviews_instead_of_hammering_the_provider(tmp_path, activate_otp, provider):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    _seed_sessions(runtime, 12)
    runtime.reviewer.save_settings({"provider": "openai", "model": "gpt-test", "api_key": "sk-bad", "mode": "automatic"})
    assert len(runtime.reviewer.pending()) == 12
    async with provider["client"](transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.post("/api/review-all", headers=headers)).json() == {"started": True}
        for _ in range(50):
            await asyncio.sleep(0.02)
            if runtime.reviewer.provider_state:
                break
        await asyncio.sleep(0.1)
        assert provider["count"] == 1  # stopped at the first rejected call, not once per session
        status = runtime.reviewer.automatic_status()
        assert "rejected the API key (HTTP 401)" in status and "paused" in status
        state = (await client.get("/api/state", headers=headers)).json()
        assert state["reviewSettings"]["automatic_status"] == status
        again = await client.post("/api/review-all", headers=headers)
        assert again.status_code == 400 and "rejected the API key" in again.json()["error"]
        assert provider["count"] == 1
        # Saving settings (e.g. a new key) lifts the pause.
        runtime.reviewer.save_settings({"api_key": "sk-new"})
        assert runtime.reviewer.automatic_status() is None and runtime.reviewer.provider_ready()


def test_backoff_rules(tmp_path):
    runtime = create_app(tmp_path).state.runtime
    reviewer = runtime.reviewer
    reviewer.save_settings({"provider": "openai", "model": "gpt-test", "api_key": "sk"})
    # Transient provider errors back off provider-wide with growing delays.
    assert reviewer.record_failure("g1", ReviewProviderError("HTTP 503", fatal=False)) is True
    assert not reviewer.provider_ready()
    first = reviewer.provider_state["retry_at"] - time.time()
    reviewer.provider_state["retry_at"] = 0
    assert reviewer.provider_ready()
    reviewer.record_failure("g1", ReviewProviderError("HTTP 503", fatal=False))
    assert reviewer.provider_state["retry_at"] - time.time() > first * 1.9
    assert "backing off" in reviewer.automatic_status()
    reviewer.record_success("g1")
    assert reviewer.provider_ready() and reviewer.automatic_status() is None
    # Session-specific failures delay only that session.
    assert reviewer.record_failure("g2", ValueError("Model did not return valid review JSON.")) is False
    assert not reviewer.grant_due("g2") and reviewer.grant_due("g3") and reviewer.provider_ready()
    assert BACKOFF_FIRST - 5 < reviewer.grant_backoff["g2"][1] - time.time() <= BACKOFF_FIRST
