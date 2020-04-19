# -*- coding: utf-8 -*-
# import requests
import schemathesis
from hypothesis import settings, HealthCheck
import werkzeug
import json
from glom import glom

from restapi.server import create_app
from restapi.services.authentication import BaseAuthentication
from restapi.utilities.logs import log


def get_auth_token():
    client = werkzeug.Client(app, werkzeug.wrappers.Response)
    BaseAuthentication.myinit()
    USER = BaseAuthentication.default_user
    PWD = BaseAuthentication.default_password
    data = {'username': USER, 'password': PWD}

    r = client.post('/auth/login', data=json.dumps(data))
    content = json.loads(r.data.decode('utf-8'))
    token = glom(content, "Response.data.token", default=None)
    if token is None:
        token = content
    return {'Authorization': 'Bearer {}'.format(token)}


app = create_app(testing_mode=True)
auth_header = get_auth_token()


for url in ['/api/swagger', '/api/specs']:
    log.info("Retreving schema from {}", url)
    schema = schemathesis.from_wsgi(url, app)

    log.info("Starting tests...")

    @schema.parametrize()
    @settings(
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_no_server_errors_no_auth(case):

        response = case.call_wsgi()

        # validation checks are defined here:
        # https://github.com/kiwicom/schemathesis/blob/master/src/schemathesis/checks.py#L99
        case.validate_response(response)

    @schema.parametrize()
    @settings(
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_no_server_errors_with_auth(case):

        if case.path == '/api/logout':
            log.warning("Skipping logout")
            return True

        if case.headers is None:
            case.headers = auth_header

        response = case.call_wsgi()

        # validation checks are defined here:
        # https://github.com/kiwicom/schemathesis/blob/master/src/schemathesis/checks.py#L99
        case.validate_response(response)

    @schema.parametrize(endpoint="/api/logout")
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
