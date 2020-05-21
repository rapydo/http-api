# -*- coding: utf-8 -*-
# import requests
import os
import schemathesis
from hypothesis import settings, HealthCheck
import werkzeug
import json
from glom import glom

from restapi.server import create_app
from restapi.services.authentication import BaseAuthentication
from restapi.utilities.logs import log


RUN_SCHEMATHESIS = os.getenv("RUN_SCHEMATHESIS", "1") == "1"


def get_auth_token():
    client = werkzeug.Client(app, werkzeug.wrappers.Response)
    BaseAuthentication.load_default_user()
    BaseAuthentication.load_roles()
    USER = BaseAuthentication.default_user
    PWD = BaseAuthentication.default_password
    data = {'username': USER, 'password': PWD}

    r = client.post('/auth/login', data=data)
    token = json.loads(r.data.decode('utf-8'))
    assert token is not None

    return {'Authorization': 'Bearer {}'.format(token)}


if not RUN_SCHEMATHESIS:
    log.warning("Skipping schemathesis")
else:
    app = create_app(testing_mode=True)
    auth_header = get_auth_token()

    schema = schemathesis.from_wsgi('/api/swagger', app)

    log.info("Starting tests...")

    @schema.parametrize()
    @settings(
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow]
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
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_with_admin_auth(case):

        if case.path == '/auth/logout':
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
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_logout(case):

        if case.headers is None:
            case.headers = auth_header

        response = case.call_wsgi()

        # validation checks are defined here:
        # https://github.com/kiwicom/schemathesis/blob/master/src/schemathesis/checks.py#L99
        case.validate_response(response)
