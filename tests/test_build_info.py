import json
from types import SimpleNamespace

from hilait import __version__
from hilait import server


def test_build_id_from_pip_git_install(monkeypatch):
    commit = "a1b2c3d4" * 5
    installed = SimpleNamespace(
        version=__version__,
        read_text=lambda name: json.dumps({"vcs_info": {"commit_id": commit}}),
    )
    monkeypatch.setattr(server, "distribution", lambda name: installed)
    assert server.build_id() == "a1b2c3d4"


def test_build_id_does_not_report_another_installed_version(monkeypatch):
    installed = SimpleNamespace(version="0.0.0", read_text=lambda name: "")
    monkeypatch.setattr(server, "distribution", lambda name: installed)
    assert server.build_id() == "source"
