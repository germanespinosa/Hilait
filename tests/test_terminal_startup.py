import paramiko

from hilait.sessions import _open_windows_shell, _shell_start_command, _windows_shell_command


def test_windows_powershell_selection_handles_missing_power_shell_7():
    command = _windows_shell_command({"platform": "windows", "shell": "powershell7"})
    assert command.startswith("powershell.exe -NoLogo -NoProfile -Command ")
    assert "Get-Command pwsh.exe -ErrorAction SilentlyContinue" in command
    assert "& powershell.exe -NoLogo" in command
    assert not command.endswith("\r")


def test_default_shell_does_not_send_startup_command():
    assert _shell_start_command({"platform": "windows", "shell": "default"}) is None
    assert _windows_shell_command({"platform": "windows", "shell": "default"}) is None
    assert _windows_shell_command({"platform": "unix", "shell": "powershell7"}) is None
    assert _shell_start_command({"platform": "unix", "shell": "powershell7"}) == "pwsh -NoLogo\r"


class FakeChannel:
    def __init__(self, refuse=False):
        self.refuse, self.calls, self.closed = refuse, [], False

    def get_pty(self, **kwargs):
        self.calls.append(("pty", kwargs))

    def exec_command(self, command):
        if self.refuse:
            raise paramiko.SSHException("exec refused")
        self.calls.append(("exec", command))

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, channel):
        self.channel = channel

    def get_transport(self):
        return self

    def open_session(self, timeout=None):
        return self.channel


def test_windows_shell_runs_as_session_command_not_typed():
    channel = FakeChannel()
    profile = {"platform": "windows", "shell": "powershell7"}
    assert _open_windows_shell(FakeClient(channel), profile) is channel
    assert channel.calls[0] == ("pty", {"term": "xterm-256color", "width": 100, "height": 30})
    assert channel.calls[1] == ("exec", _windows_shell_command(profile))


def test_windows_shell_falls_back_when_exec_is_refused():
    channel = FakeChannel(refuse=True)
    assert _open_windows_shell(FakeClient(channel), {"platform": "windows", "shell": "powershell5"}) is None
    assert channel.closed
    assert _open_windows_shell(FakeClient(FakeChannel()), {"platform": "windows", "shell": "default"}) is None
