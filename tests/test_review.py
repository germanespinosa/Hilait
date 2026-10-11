"""Review evidence boundaries, provider protocols, and score alerts."""

import base64
import json

import httpx
import pytest

from hilait import review as review_module
from hilait.ntfy import NtfyNotifier
from hilait.review import Reviewer
from hilait.server import create_app
from hilait.storage import Audit, Store


def recorded_session(tmp_path):
    store = Store(tmp_path)
    audit = Audit(store)
    context = {"grant": "grant-1", "agent": "Agent", "connection": "Machine",
               "purpose": "Inspect service status and report findings without changing files."}
    audit.write("access_requested", context, {"purpose": context["purpose"]})
    audit.write("terminal_input_sent", context, {"base64": base64.b64encode(b"service status\n").decode()})
    audit.write("terminal_output", context, {"base64": base64.b64encode(b"PRIVATE OUTPUT\n").decode()})
    audit.write("file_request", context, {"action": "write", "path": "/tmp/report",
                                          "base64": base64.b64encode(b"PRIVATE FILE").decode()})
    audit.write("file_result", context, {"action": "read", "path": "/tmp/report",
                                         "result": {"base64": base64.b64encode(b"PRIVATE FILE").decode()}})
    audit.write("session_closed", context, {"reason": "Agent completed the task"})
    return store, audit


def test_evidence_hash_reuses_unchanged_session_index(tmp_path, monkeypatch):
    store, audit = recorded_session(tmp_path)
    reviewer = Reviewer(store, audit)
    session = audit.session
    reads = []
    def counted(grant):
        reads.append(grant)
        return session(grant)
    monkeypatch.setattr(audit, "session", counted)
    original = reviewer.evidence_hash("grant-1")
    assert reviewer.evidence_hash("grant-1") == original
    assert reads == ["grant-1"]
    audit.write("terminal_output", {"grant": "grant-1"}, {"base64": base64.b64encode(b"NEW OUTPUT").decode()})
    assert reviewer.evidence_hash("grant-1") != original
    assert reads == ["grant-1", "grant-1"]


def test_light_review_explains_menu_input_without_sending_command_results(tmp_path):
    store = Store(tmp_path)
    audit = Audit(store)
    context = {"grant": "menu-session", "purpose": "Inspect DHCP mappings and DNS rewrites."}
    audit.write("access_requested", context, {"purpose": context["purpose"]})
    menu = b"WAN address: 73.176.134.10\r\n  7) Ping host     8) Shell\r\n  9) pfTop         10) Firewall Log\r\nEnter an option: "
    audit.write("terminal_output", context, {"base64": base64.b64encode(menu).decode()})
    audit.write("terminal_input_sent", context, {"base64": base64.b64encode(b"8\nsh\n").decode()})
    audit.write("terminal_output", context, {"base64": base64.b64encode(b"root@gateway:~ # ").decode()})
    audit.write("terminal_input_sent", context, {"base64": base64.b64encode(b"python3 check.py\n").decode()})
    evidence = Reviewer(store, audit).evidence("menu-session", "light")
    first, second = evidence["instructions"]
    assert first["instruction"] == "8\nsh\n"
    assert "8) Shell" in first["context_before"]
    assert "Enter an option:" in first["context_before"]
    assert "WAN address" not in json.dumps(evidence)
    assert second["context_before"] == "root@gateway:~ #"
    assert "terminal_output" not in json.dumps(evidence)
    assert "numbered menu selection" in review_module.RUBRIC


@pytest.mark.asyncio
async def test_light_excludes_outputs_and_deep_scores_correctness(tmp_path, monkeypatch):
    store, audit = recorded_session(tmp_path)
    reviewer = Reviewer(store, audit)
    reviewer.save_settings({"provider": "local", "endpoint": "http://localhost:11434/v1",
                            "model": "test-model", "review_level": "light"})
    seen = []

    async def fake_model(settings, evidence, prompt, update):
        seen.append((json.loads(evidence), prompt))
        if settings["review_level"] == "light":
            return json.dumps({"safety": 8, "purpose_alignment": 9, "summary": "Instructions match the stated inspection.",
                               "rationale": {"safety": "No dangerous action in #2.", "purpose_alignment": "#2 inspects status."},
                               "evidence_refs": {"safety": [2], "purpose_alignment": [2]},
                               "findings": []})
        return json.dumps({"safety": 8, "purpose_alignment": 9, "correctness": 7,
                           "summary": "The output supports the inspection, but verification is limited.",
                           "rationale": {"safety": "No risky action.", "purpose_alignment": "Actions match request.",
                                         "correctness": "Output is present; no follow-up check."},
                           "evidence_refs": {"safety": [2, 999], "purpose_alignment": [2], "correctness": [3, 6]},
                           "findings": [{"sequence": 2, "label": "unnecessary", "axes": ["purpose_alignment"],
                                         "rationale": "Example finding."}]})

    monkeypatch.setattr(reviewer, "_call_model", fake_model)
    light = await reviewer.review("grant-1")
    assert light["correctness"] is None
    assert light["level"] == "light"
    light_evidence = json.dumps(seen[0][0])
    assert "PRIVATE OUTPUT" not in light_evidence
    assert "PRIVATE FILE" not in light_evidence
    assert "terminal_output" not in light_evidence
    assert "session_closed" not in light_evidence
    assert "service status" in light_evidence
    assert "file_request" in light_evidence
    assert "correctness" not in seen[0][1].split("JSON keys:")[1]
    assert reviewer.pending() == []

    reviewer.save_settings({"review_level": "deep"})
    assert reviewer.pending() == ["grant-1"]
    deep = await reviewer.review("grant-1")
    assert deep["correctness"] == 7
    deep_evidence = json.dumps(seen[1][0])
    assert "PRIVATE OUTPUT" in deep_evidence
    assert "PRIVATE FILE" in deep_evidence
    assert "session_closed" in deep_evidence
    assert deep["evidence_refs"]["safety"] == [2]
    assert deep["evidence_refs"]["correctness"] == [3, 6]
    assert deep["findings"][0]["axes"] == ["purpose_alignment"]
    assert deep["schema_version"] == 3
    assert reviewer.pending() == []


def test_provider_change_does_not_reuse_saved_api_key(tmp_path):
    store, audit = recorded_session(tmp_path)
    reviewer = Reviewer(store, audit)
    reviewer.save_settings({"provider": "openai", "endpoint": "https://api.openai.com/v1",
                            "model": "model-a", "api_key": "private-key"})
    assert store.decrypt(reviewer.settings()["api_key"]) == "private-key"
    assert "private-key" not in json.dumps(reviewer.public_settings())
    reviewer.save_settings({"provider": "anthropic", "endpoint": "https://api.anthropic.com/v1",
                            "model": "model-b"})
    assert reviewer.settings()["api_key"] == ""
    with pytest.raises(ValueError, match="HTTPS"):
        reviewer.save_settings({"provider": "openai", "endpoint": "http://example.com/v1"})


@pytest.mark.asyncio
async def test_extend_authorization_can_become_permanent(tmp_path, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    agent, _ = runtime.store.create_agent("Extension fixture")
    profile = {"id": "extension-machine", "name": "Extension machine", "host": "localhost", "port": 22,
               "username": "fixture", "platform": "unix", "shell": "default", "allowed_agent_ids": None}
    runtime.store.save_profiles([profile])
    authorization = runtime.agents.create_authorization(agent["id"], profile["id"], 1, "Remote")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        endpoint = f"/api/authorizations/{authorization['id']}/extend"
        invalid = await client.post(endpoint, headers=headers, json={"hours": 1, "permanent": True})
        assert invalid.status_code == 400
        assert not runtime.agents.authorizations()[0]["permanent"]

        extended = await client.post(endpoint, headers=headers, json={"hours": 1})
        assert extended.status_code == 200, extended.text
        assert extended.json()["expires_utc"] > authorization["expires_utc"]

        permanent = await client.post(endpoint, headers=headers, json={"permanent": True})
        assert permanent.status_code == 200, permanent.text
        assert permanent.json()["permanent"] is True
        assert permanent.json()["expires_utc"] is None
        assert permanent.json()["file_access"] == "Remote"
        assert runtime.agents.active_authorization(agent["id"], profile["id"])["id"] == authorization["id"]
        assert runtime.store.read("authorizations.json", [])[0]["permanent"] is True
        assert (await client.post(endpoint, headers=headers, json={"hours": 1})).status_code == 400


@pytest.mark.asyncio
async def test_change_authorization_file_access(tmp_path, activate_otp, monkeypatch):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    agent, _ = runtime.store.create_agent("File scope fixture")
    profile = {"id": "file-scope-machine", "name": "File scope machine", "host": "localhost", "port": 22,
               "username": "fixture", "platform": "unix", "shell": "default", "allowed_agent_ids": None}
    runtime.store.save_profiles([profile])
    authorization = runtime.agents.create_authorization(agent["id"], profile["id"], None, "None", permanent=True)
    endpoint = f"/api/authorizations/{authorization['id']}/file-access"
    auto_approved = []

    async def approve(grant_id, **_kwargs):
        auto_approved.append(grant_id)

    monkeypatch.setattr(runtime.agents, "approve", approve)
    purpose = "Inspect a known fixture for the approved maintenance task and report the result clearly."

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.post(endpoint, json={"file_access": "Remote"})).status_code == 401
        assert (await client.post(endpoint, headers=headers, json={"file_access": "Invalid"})).status_code == 400
        assert (await client.post(endpoint, headers=headers, json={"file_access": "LocalTransfers"})).status_code == 400
        assert runtime.agents.active_authorization(agent["id"], profile["id"])["file_access"] == "None"
        await runtime.agents.request(agent, profile["id"], purpose, "Remote")
        assert auto_approved == []

        remote = await client.post(endpoint, headers=headers, json={"file_access": "Remote"})
        assert remote.status_code == 200, remote.text
        assert remote.json()["file_access"] == "Remote"
        await runtime.agents.request(agent, profile["id"], purpose, "Remote")
        assert len(auto_approved) == 1

        local = await client.post(endpoint, headers=headers,
                                  json={"file_access": "LocalTransfers", "local_folder": " /srv/hilait-transfer "})
        assert local.status_code == 200, local.text
        assert local.json()["local_folder"] == "/srv/hilait-transfer"
        assert runtime.store.read("authorizations.json", [])[0]["file_access"] == "LocalTransfers"

        off = await client.post(endpoint, headers=headers, json={"file_access": "None"})
        assert off.status_code == 200, off.text
        assert off.json()["local_folder"] is None
        assert runtime.agents.active_authorization(agent["id"], profile["id"])["file_access"] == "None"
        assert any(record["kind"] == "automatic_approval_file_access_changed"
                   for record in runtime.audit.records())

        runtime.agents.revoke_authorization(authorization["id"])
        assert (await client.post(endpoint, headers=headers, json={"file_access": "Remote"})).status_code == 404


@pytest.mark.asyncio
async def test_permanent_authorization_and_low_score_revocation(tmp_path, monkeypatch, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    admin_session = activate_otp(runtime)
    agent, _ = runtime.store.create_agent("Review fixture")
    profile = {"id": "review-machine", "name": "Review machine", "host": "localhost", "port": 22,
               "username": "fixture", "platform": "unix", "shell": "default", "allowed_agent_ids": None}
    runtime.store.save_profiles([profile])
    grant = await runtime.agents.request(agent, profile["id"],
                                         "Inspect the fixture machine and report its state without changing any files or services.")
    assert grant.state == "Pending"
    authorization = runtime.agents.create_authorization(agent["id"], profile["id"], None, "Remote", permanent=True)
    assert authorization["expires_utc"] is None
    assert runtime.agents.active_authorization(agent["id"], profile["id"])["id"] == authorization["id"]
    with pytest.raises(ValueError, match="Permanent"):
        runtime.agents.extend_authorization(authorization["id"], 1)
    runtime.reviewer.save_settings({"revoke_thresholds": {"safety": 3, "purpose_alignment": 2, "correctness": None}})
    with pytest.raises(ValueError, match="threshold"):
        runtime.reviewer.save_settings({"revoke_thresholds": {"safety": 11}})
    runtime.agents.change(grant, "Approved", "Test approval")
    grant.session_id = "review-session"
    runtime.sessions.sessions[grant.session_id] = object()
    closed = []

    async def close_session(session_id, reason):
        closed.append((session_id, reason))
        runtime.sessions.sessions.pop(session_id)

    monkeypatch.setattr(runtime.sessions, "close", close_session)

    async def low_review(_grant_id, _progress):
        return {"safety": 2, "purpose_alignment": 8, "correctness": 8, "reviewed_utc": "2026-10-11T00:00:00+00:00"}

    monkeypatch.setattr(runtime.reviewer, "review", low_review)
    headers = {"Authorization": "Bearer " + admin_session}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post(f"/api/review/{grant.id}", headers=headers)
        assert response.status_code == 200, response.text
        assert grant.state == "Revoked"
        assert closed[0][0] == "review-session"
        assert runtime.agents.active_authorization(agent["id"], profile["id"]) is None
        with pytest.raises(PermissionError):
            runtime.agents.owned(agent, grant.id, active=True)
        assert any(record["kind"] == "review_access_revoked" for record in runtime.audit.session(grant.id))
        renewed = runtime.agents.create_authorization(agent["id"], profile["id"], None, "Remote", permanent=True)
        await client.post(f"/api/review/{grant.id}", headers=headers)
        assert runtime.agents.active_authorization(agent["id"], profile["id"])["id"] == renewed["id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("provider,endpoint,target,reply", [
    ("local", "http://localhost:11434/api", "/api/chat", {"message": {"content": "ANSWER"}}),
    ("openai", "https://api.openai.com/v1", "/v1/chat/completions", {"choices": [{"delta": {"content": "ANSWER"}}]}),
    ("grok", "https://api.x.ai/v1", "/v1/chat/completions", {"choices": [{"delta": {"content": "ANSWER"}}]}),
    ("anthropic", "https://api.anthropic.com/v1", "/v1/messages",
     {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "ANSWER"}}),
])
async def test_provider_request_protocols(tmp_path, monkeypatch, provider, endpoint, target, reply):
    store, audit = recorded_session(tmp_path)
    reviewer = Reviewer(store, audit)
    reviewer.save_settings({"provider": provider, "endpoint": endpoint, "model": "test-model", "api_key": "test-key"})
    captured = []

    def handler(request):
        captured.append(request)
        assert request.url.path == target
        if provider == "anthropic":
            assert request.headers["x-api-key"] == "test-key"
            assert request.headers["anthropic-version"] == "2023-06-01"
            assert json.loads(request.content)["system"]
        else:
            assert request.headers["authorization"] == "Bearer test-key"
            assert json.loads(request.content)["messages"][0]["role"] == "system"
        content = json.dumps(reply) + "\n" if provider == "local" else "data: " + json.dumps(reply) + "\n\ndata: [DONE]\n\n"
        return httpx.Response(200, text=content)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(review_module.httpx, "AsyncClient",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    answer = await reviewer._call_model(reviewer.settings(), "{}", "Review this.", lambda _: None)
    assert answer == "ANSWER"
    assert len(captured) == 1


@pytest.mark.asyncio
async def test_score_alert_only_for_configured_threshold(tmp_path, monkeypatch):
    store, audit = recorded_session(tmp_path)
    notifier = NtfyNotifier(store, audit)
    notifier.save({"enabled": False, "server_url": "https://ntfy.example", "topic": "reviews",
                   "hilait_url": "https://hilait.example"})
    sent = []

    async def capture(config, payload):
        sent.append(payload)

    monkeypatch.setattr(notifier, "_post", capture)
    result = {"safety": 3, "purpose_alignment": 8, "correctness": None,
              "summary": "One instruction could expose credentials."}
    assert await notifier.notify_review("grant-1", result,
                                         {"safety": 4, "purpose_alignment": 4, "correctness": None})
    assert len(sent) == 1
    assert "safety 3/10" in sent[0]["message"]
    assert "purpose alignment" not in sent[0]["message"]
    assert "One instruction" in sent[0]["message"]
    assert not await notifier.notify_review("grant-1", result,
                                             {"safety": 4, "purpose_alignment": 4, "correctness": None})
    assert not await notifier.notify_review("grant-1", result,
                                             {"safety": 2, "purpose_alignment": 4, "correctness": None})
    assert len(sent) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("provider,endpoint,path,body", [
    ("local", "http://localhost:11434/api", "/api/tags", {"models": [{"name": "local-model"}]}),
    ("openai", "https://api.openai.com/v1", "/v1/models", {"data": [{"id": "openai-model"}]}),
    ("anthropic", "https://api.anthropic.com/v1", "/v1/models", {"data": [{"id": "claude-model"}]}),
    ("grok", "https://api.x.ai/v1", "/v1/language-models", {"models": [{"id": "grok-model"}]}),
])
async def test_provider_model_listing(tmp_path, monkeypatch, provider, endpoint, path, body):
    store, audit = recorded_session(tmp_path)
    reviewer = Reviewer(store, audit)

    def handler(request):
        assert request.url.path == path
        if provider == "anthropic":
            assert request.headers["x-api-key"] == "test-key"
        else:
            assert request.headers["authorization"] == "Bearer test-key"
        return httpx.Response(200, json=body)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(review_module.httpx, "AsyncClient",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    assert await reviewer.models(endpoint, "test-key", provider) == [next(iter(body.values()))[0].get("id") or next(iter(body.values()))[0]["name"]]


@pytest.mark.asyncio
async def test_review_endpoint_notifies_once_for_new_low_score(tmp_path, monkeypatch, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    admin = {"Authorization": "Bearer " + activate_otp(runtime)}
    context = {"grant": "grant-1", "agent": "Agent", "connection": "Machine", "purpose": "Check service status."}
    runtime.audit.write("access_requested", context, {"purpose": context["purpose"]})
    runtime.audit.write("terminal_input_sent", context, {"base64": base64.b64encode(b"status\n").decode()})
    runtime.reviewer.save_settings({"model": "test-model", "review_level": "light",
                                    "alert_thresholds": {"safety": 4, "purpose_alignment": None, "correctness": None}})
    runtime.ntfy.save({"enabled": False, "server_url": "https://ntfy.example", "topic": "reviews",
                       "hilait_url": "https://hilait.example"})
    sent = []

    async def fake_model(settings, evidence, prompt, update):
        return json.dumps({"safety": 3, "purpose_alignment": 8, "summary": "This command may expose a credential.",
                           "rationale": {"safety": "Potential credential exposure.", "purpose_alignment": "Relevant status check."},
                           "findings": []})

    async def capture(config, payload):
        sent.append(payload)

    monkeypatch.setattr(runtime.reviewer, "_call_model", fake_model)
    monkeypatch.setattr(runtime.ntfy, "_post", capture)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        for _ in range(2):
            response = await client.post("/api/review/grant-1", headers=admin, json={})
            assert response.status_code == 200, response.text
    assert len(sent) == 1
    assert "safety 3/10" in sent[0]["message"]
