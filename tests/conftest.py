import time

import pytest

from hilait.admin_auth import AdminAuth, totp


@pytest.fixture
def activate_otp():
    def activate(runtime):
        auth = runtime.auth if hasattr(runtime, "auth") else AdminAuth(runtime)
        setup = auth.begin_setup()
        return auth.confirm_setup(totp(setup["secret"], time.time()))
    return activate
