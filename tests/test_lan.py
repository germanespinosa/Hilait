"""LAN mode must configure HTTPS and retain one stable local identity."""

import hashlib
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from hilait import cli
from hilait.admin_auth import totp
from hilait.server import create_app
from hilait import tls


def test_lan_certificate_is_reused_and_matches_printed_fingerprint(tmp_path, monkeypatch):
    monkeypatch.setattr(tls, "lan_addresses", lambda: ["10.0.10.5"])
    certificate, key, fingerprint, addresses = tls.ensure_lan_certificate(tmp_path)
    parsed = x509.load_pem_x509_certificate(certificate.read_bytes())
    assert fingerprint == hashlib.sha256(parsed.public_bytes(serialization.Encoding.DER)).hexdigest()
    assert addresses == ["10.0.10.5"]
    assert "10.0.10.5" in str(parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    original_key = key.read_bytes()
    assert tls.ensure_lan_certificate(tmp_path)[:3] == (certificate, key, fingerprint)
    assert key.read_bytes() == original_key


def test_lan_cli_binds_https_without_changing_admin_token(tmp_path, monkeypatch, capsys):
    app = create_app(tmp_path)
    monkeypatch.setattr(cli, "create_app", lambda: app)
    monkeypatch.setattr(tls, "lan_addresses", lambda: ["10.0.10.5"])
    # cli imported the function, which still resolves lan_addresses in tls.py.
    observed = {}
    monkeypatch.setattr(cli.uvicorn, "run", lambda *args, **kwargs: observed.update(kwargs))
    monkeypatch.setattr(sys, "argv", ["hilait", "serve", "--lan"])
    cli.main()
    output = capsys.readouterr().out
    assert "https://10.0.10.5:8765" in output
    assert app.state.runtime.store.admin_token in output
    assert observed["host"] == "0.0.0.0"
    assert observed["ssl_certfile"] and observed["ssl_keyfile"]


def test_cli_opens_otp_login_without_printing_admin_token(tmp_path, monkeypatch, capsys):
    app = create_app(tmp_path)
    auth = app.state.runtime.auth
    setup = auth.begin_setup()
    auth.confirm_setup(totp(setup["secret"], time.time()))
    monkeypatch.setattr(cli, "create_app", lambda: app)
    opened = []
    monkeypatch.setattr(cli.webbrowser, "open", opened.append)
    monkeypatch.setattr(cli.uvicorn, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(sys, "argv", ["hilait", "serve", "--open"])
    cli.main()
    assert opened == ["http://127.0.0.1:8765/"]
    output = capsys.readouterr().out
    assert "OTP enabled" in output
    assert app.state.runtime.store.admin_token not in output
