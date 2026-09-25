"""Loopback-only SSH/SFTP server for integration tests. No system shell is executed."""
import asyncio
import pathlib
import sys
import shlex
import asyncssh

root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)

class Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True
    def password_auth_supported(self):
        return True
    def validate_password(self, username, password):
        return username == 'harbor-test' and password == 'loopback-fixture-only'

async def shell(process):
    if process.command:
        # Emulate sudo's isolated stdin contract; never execute a system command.
        args = shlex.split(process.command)
        if args[:7] != ['/usr/bin/sudo', '-k', '-S', '-p', '', '/bin/sh', '-lc'] or len(args) != 8:
            process.stderr.write('Invalid managed sudo invocation\n')
            process.exit(2)
            return
        supplied = await process.stdin.readline()
        if supplied != 'fixture-sudo-secret\n':
            process.stderr.write('sudo: authentication failed\n')
            process.exit(1)
            return
        if 'wait-for-cancel' in args[7]:
            process.stdout.write('fixture awaiting cancellation\n')
            await asyncio.sleep(60)
            process.exit(0)
            return
        process.stdout.write('managed sudo succeeded\n')
        process.exit(0)
        return
    process.stdout.write('Harbor fixture — 日本語 café 😀\r\n')
    while True:
        try:
            line = await process.stdin.readline()
            if not line or line.strip() == 'exit':
                process.exit(0)
                return
            process.stdout.write('echo: ' + line)
        except asyncssh.TerminalSizeChanged:
            pass

async def main():
    server = await asyncssh.create_server(Server, '127.0.0.1', 0,
        server_host_keys=[asyncssh.generate_private_key('ssh-ed25519')],
        process_factory=shell,
        sftp_factory=lambda channel: asyncssh.SFTPServer(channel, chroot=str(root)))
    print(server.get_port(), flush=True)
    await asyncio.Future()

asyncio.run(main())
