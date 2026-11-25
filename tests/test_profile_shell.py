from hilait.storage import Store


def test_agent_view_and_sessions_have_no_shell_selection(tmp_path):
    import hilait.sessions as sessions
    assert not hasattr(sessions, "_shell_start_command")
    store = Store(tmp_path / "data")
    view = store.public_profile({"id": "p", "name": "box", "platform": "windows", "shell": "powershell7"}, agent=True)
    assert "shell" not in view
