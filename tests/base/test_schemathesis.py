# -*- coding: utf-8 -*-
# import requests
import schemathesis
from hypothesis import settings
import werkzeug
import json
from glom import glom

from restapi.server import create_app
from restapi.services.authentication import BaseAuthentication

app = create_app(testing_mode=True)
schema = schemathesis.from_wsgi("/api/specs", app)


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


auth_header = get_auth_token()


@schema.parametrize()
@settings(deadline=None)
def test_no_server_errors_no_auth(case):

    response = case.call_wsgi()

    # validation cheks are defined here:
    # https://github.com/kiwicom/schemathesis/blob/master/src/schemathesis/checks.py#L99
    case.validate_response(response)


@schema.parametrize()
@settings(deadline=None)
def test_no_server_errors_with_auth(case):

    if case.headers is None:
        case.headers = auth_header

    response = case.call_wsgi()

    # validation cheks are defined here:
    # https://github.com/kiwicom/schemathesis/blob/master/src/schemathesis/checks.py#L99
    case.validate_response(response)
