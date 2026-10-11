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
    first = audit._record_path(1)
    assert first.exists()
    assert "access_requested" not in first.read_text()
    assert len(list(audit.path.rglob("*.audit"))) == 2
    assert len(audit.session("g1")) == 2
    audit.delete_session("g1")
    assert not audit.session("g1")
    assert audit.records()[-1]["kind"] == "session_log_deleted"
    audit.write("check", {}, {})
    first = audit._record_path(1)
    second = audit._record_path(2)
    second.write_bytes(first.read_bytes())
    with pytest.raises(ValueError, match="chain"):
        audit.records()


def test_legacy_audit_migrates_without_changing_chain(tmp_path):
    store = Store(tmp_path)
    first = {"sequence": 1, "utc": "2026-01-01T00:00:00+00:00", "kind": "access_requested",
             "context": {"grant": "g1"}, "data": {"purpose": "Preserve this"}, "previous": ""}
    import base64
    import hashlib
    line1 = base64.b64encode(store.cipher.encrypt(json.dumps(first).encode()))
    second = {**first, "sequence": 2, "kind": "terminal_output", "previous": hashlib.sha256(line1).hexdigest()}
    line2 = base64.b64encode(store.cipher.encrypt(json.dumps(second).encode()))
    legacy = tmp_path / "activity.audit"
    legacy.write_bytes(line1 + b"\n" + line2 + b"\n")
    legacy.chmod(0o600)
    audit = Audit(store)
    assert [r["kind"] for r in audit.records()] == ["access_requested", "terminal_output"]
    assert audit.records()[1]["_hash"] == hashlib.sha256(line2).hexdigest()
    assert not legacy.exists()
    assert audit._record_path(1).read_bytes() == line1
    audit.write("access_state", {"grant": "g1"}, {"state": "Approved"})
    assert len(Audit(Store(tmp_path)).records()) == 3


def test_failed_legacy_migration_keeps_original_log(tmp_path, monkeypatch):
    import base64
    store = Store(tmp_path)
    record = {"sequence": 1, "utc": "2026-01-01T00:00:00+00:00", "kind": "access_requested",
              "context": {"grant": "g1"}, "data": None, "previous": ""}
    legacy = tmp_path / "activity.audit"
    original = base64.b64encode(store.cipher.encrypt(json.dumps(record).encode())) + b"\n"
    legacy.write_bytes(original)
    legacy.chmod(0o600)
    put_line = Audit._put_line
    def fail_after_write(self, sequence, line, generation=None):
        put_line(self, sequence, line, generation)
        raise OSError("interrupted migration")
    with monkeypatch.context() as patch:
        patch.setattr(Audit, "_put_line", fail_after_write)
        with pytest.raises(OSError, match="interrupted"):
            Audit(store)
    assert legacy.read_bytes() == original
    assert not (tmp_path / "activity-records.current").exists()
    assert len(Audit(Store(tmp_path)).records()) == 1
    assert not legacy.exists()


def test_session_index_avoids_full_scan_and_tracks_new_records(tmp_path, monkeypatch):
    audit = Audit(Store(tmp_path))
    audit.write("access_requested", {"grant": "g1", "purpose": "One"})
    audit.write("access_requested", {"grant": "g2", "purpose": "Two"})
    version = audit.grant_version("g1")
    monkeypatch.setattr(audit, "_read_generation", lambda generation: pytest.fail("unexpected full audit scan"))
    assert [record["sequence"] for record in audit.session("g1")] == [1]
    assert {item["grant"] for item in audit.log_summaries()} == {"g1", "g2"}
    audit.write("terminal_output", {"grant": "g1"}, {"base64": "YWJj"})
    assert audit.grant_version("g1") != version
    assert [record["sequence"] for record in audit.session("g1")] == [1, 3]
    assert [record["sequence"] for record in audit.session("g2")] == [2]


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
