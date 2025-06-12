import pytest


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    rep = yield

    # we only look at actual failing test calls, not setup/teardown
    if rep.when == "call" and rep.failed:
        with open("/tmp/valkey-ldap.log", "r") as log_file:
            logs = log_file.read()
        rep.sections.append(("Valkey and LDAP Services Logs", logs))

    return rep
