from hilait.sessions import _shell_start_command


def test_windows_powershell_selection_handles_missing_power_shell_7():
    command = _shell_start_command({"platform": "windows", "shell": "powershell7"})
    assert command.startswith("powershell.exe -NoLogo -NoProfile -Command ")
    assert "Get-Command pwsh.exe -ErrorAction SilentlyContinue" in command
    assert "& powershell.exe -NoLogo" in command
    assert command.endswith("\r")


def test_default_shell_does_not_send_startup_command():
    assert _shell_start_command({"platform": "windows", "shell": "default"}) is None
