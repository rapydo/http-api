import json

import schemathesis
import werkzeug
from hypothesis import HealthCheck, settings

from restapi.env import Env
from restapi.server import create_app
from restapi.services.authentication import BaseAuthentication
from restapi.tests import BaseTests, get_faker
from restapi.utilities.logs import log, set_logger

RUN_SCHEMATHESIS = Env.get_bool("RUN_SCHEMATHESIS")


def get_auth_token(client, data):

    data["totp_code"] = BaseTests.generate_totp(data.get("username"))
    r = client.post("/auth/login", data=data)
    content = json.loads(r.data.decode("utf-8"))

    if r.status_code == 403:
        if isinstance(content, dict) and content.get("actions"):
            actions = content.get("actions", {})

            if "FIRST LOGIN" in actions or "PASSWORD EXPIRED" in actions:
                currentpwd = data["password"]
                fake = get_faker()
                newpwd = fake.password(strong=True)
                data["new_password"] = newpwd
                data["password_confirm"] = newpwd
                # Change the password to silence FIRST_LOGIN and PASSWORD_EXPIRED
                get_auth_token(client, data)
                # Change again to restore the default password
                # and keep all other tests fully working
                data["password"] = newpwd
                data["new_password"] = currentpwd
                data["password_confirm"] = currentpwd
                return get_auth_token(client, data)

    assert r.status_code == 200
    assert content is not None

    return content, {"Authorization": f"Bearer {content}"}


# Schemathesis is always enabled during core tests
if not RUN_SCHEMATHESIS:  # pragma: no cover
    log.warning("Skipping schemathesis")
else:
    # No need to restore the logger after this test because
    # schemathesis test is the last one!
    # (just because in alphabetic order there are no other tests)
    set_logger("WARNING")
    app = create_app()
    client = werkzeug.Client(app, werkzeug.wrappers.Response)
    BaseAuthentication.load_default_user()
    BaseAuthentication.load_roles()
    USER = BaseAuthentication.default_user
    PWD = BaseAuthentication.default_password
    data = {"username": USER, "password": PWD}
    token, auth_header = get_auth_token(client, data)

    # it does not handle custom headers => the endpoint will provide partial schema
    # due to missing authentication => skipping all private endpoints and schemas
    # schema = schemathesis.from_wsgi('/api/swagger', app)
    r = client.get(f"/api/swagger?access_token={token}")
    assert r.status_code == 200
    schema = json.loads(r.get_data().decode())
    schema = schemathesis.from_dict(schema, app=app)

    log.info("Starting tests...")

    @schema.parametrize()
    @settings(
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
    )
    def test_no_auth(case):

        response = case.call_wsgi()

        # I want to allow 503 errors, raised in case of mail sending not enabled
        # Let's convert to 404 errors
        if response.status_code == 503:
            response.status_code = 404

        # validation checks are defined here:
        # https://github.com/kiwicom/schemathesis/blob/master/src/schemathesis/checks.py#L99
        case.validate_response(response)

    @schema.parametrize()
    @settings(
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
    )
    def test_with_admin_auth(case):

        if case.path == "/auth/logout":
            log.warning("Skipping logout")
            return None

        if case.headers is None:
            case.headers = auth_header

        response = case.call_wsgi()

        # I want to allow 503 errors, raised in case of mail sending not enabled
        # Let's convert to 404 errors
        if response.status_code == 503:
            response.status_code = 404

        # validation checks are defined here:
        # https://github.com/kiwicom/schemathesis/blob/master/src/schemathesis/checks.py#L99
        case.validate_response(response)

    # FIXME: TO BE IMPLEMENTED
    # def test_with_user_auth(case):
    #     pass

    @schema.parametrize(endpoint="/auth/logout")
    @settings(
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
    )
    def test_logout(case):

        if case.headers is None:
            case.headers = auth_header

        response = case.call_wsgi()

        # validation checks are defined here:
        # https://github.com/kiwicom/schemathesis/blob/master/src/schemathesis/checks.py#L99
        case.validate_response(response)
