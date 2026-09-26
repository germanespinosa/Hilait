import json

import pytest

from hilait.files import local_path, remote_path
from hilait.storage import Audit, Store


def test_encrypted_storage_and_audit_chain(tmp_path, activate_otp):
    store = Store(tmp_path)
    with pytest.raises(PermissionError):
        store.save_profiles([{"id": "one", "name": "Fixture"}])
    activate_otp(store)
    secret = store.encrypt("unique-private-password")
    store.save_profiles([{"id": "one", "name": "Fixture", "secret": secret}])
    assert "unique-private-password" not in (tmp_path / "connections.json").read_text()
    assert "Fixture" not in (tmp_path / "connections.json").read_text()
    assert store.decrypt(store.profiles()[0]["secret"]) == "unique-private-password"
    store.write("known-hosts.json", {"private.example:22": "fingerprint"})
    store.write("authorizations.json", [{"connection": "Fixture", "profile_id": "one"}])
    assert "private.example" not in (tmp_path / "known-hosts.json").read_text()
    assert "Fixture" not in (tmp_path / "authorizations.json").read_text()
    assert store.read("known-hosts.json", {}) == {"private.example:22": "fingerprint"}
    store.write_secure("reviews.enc", {"g1": {"rationale": "sensitive session finding"}})
    assert "sensitive session finding" not in (tmp_path / "reviews.enc").read_text()
    assert store.read_secure("reviews.enc", {})["g1"]["rationale"] == "sensitive session finding"
    audit = Audit(store)
    audit.write("access_requested", {"grant": "g1"}, {"purpose": "test"})
    audit.write("terminal_output", {"grant": "g1"}, {"base64": "YWJj"})
    assert "access_requested" not in (tmp_path / "activity.audit").read_text()
    assert len(audit.session("g1")) == 2
    audit.delete_session("g1")
    assert not audit.session("g1")
    assert audit.records()[-1]["kind"] == "session_log_deleted"
    raw = (tmp_path / "activity.audit").read_bytes()
    (tmp_path / "activity.audit").write_bytes(raw + raw.splitlines()[0] + b"\n")
    with pytest.raises(ValueError, match="chain"):
        audit.records()


def test_agent_tokens_are_distinct_and_concealed(tmp_path):
    store = Store(tmp_path)
    first, token = store.create_agent("Test agent")
    second, other = store.create_agent("Another agent")
    assert token != other
    assert store.agent_for_token(token)["id"] == first["id"]
    with pytest.raises(KeyError):
        store.agent_for_token("invalid")
    assert token not in (tmp_path / "agents.json").read_text()
    config = store.agent_config(first["id"])
    assert config["mcpServers"]["hilait"]["env"]["HILAIT_AGENT_TOKEN"] == token


def test_remote_and_local_paths_are_bounded(tmp_path):
    assert remote_path(r"C:\Users\Ada", windows=True) == "/C:/Users/Ada"
    with pytest.raises(ValueError):
        remote_path("/tmp/../secret")
    with pytest.raises(ValueError):
        remote_path("/C:/CON.txt", windows=True)
    folder = tmp_path / "allowed"
    folder.mkdir()
    assert local_path(str(folder), "file.txt") == folder / "file.txt"
    with pytest.raises(PermissionError):
        local_path(str(folder), "../outside.txt")
