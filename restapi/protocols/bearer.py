# -*- coding: utf-8 -*-

"""
The tokens used are RFC6750 Bearer tokens.

The Resource should validate the tokens using the token validation endpoint;
its basic use is by adding
'Authorization: Bearer ' + tokenString to the HTTP header;
cf. RFC6749 section 7.1.

Note that anyone can validate a token as it is a bearer token:
there is no client id nor is client authentication required.
"""

from functools import wraps
from flask import request
from restapi.services.detect import Detector
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.meta import Meta
from restapi.utilities.logs import log

# Few costants
HTTPAUTH_DEFAULT_SCHEME = "Bearer"
HTTPAUTH_DEFAULT_REALM = "Authentication Required"
HTTPAUTH_TOKEN_KEY = 'Token'
HTTPAUTH_AUTH_HEADER = 'WWW-Authenticate'
HTTPAUTH_AUTH_FIELD = 'Authorization'

ALLOW_ACCESS_TOKEN_PARAMETER = (
    Detector.get_global_var('ALLOW_ACCESS_TOKEN_PARAMETER', default='False') == 'True'
)


class HTTPTokenAuth:
    """
    A class to implement a Generic Token (oauth2-like) authentication.
    Started on a draft of the great miguel: http://bit.ly/2nTqQKA
    """

    def __init__(self, scheme=None, realm=None):
        self._scheme = scheme or HTTPAUTH_DEFAULT_SCHEME
        self._realm = realm or HTTPAUTH_DEFAULT_REALM

    def get_scheme(self):
        return self._scheme

    def authenticate_header(self):
        return '{0} realm="{1}"'.format(self._scheme, self._realm)

    def authenticate(self, verify_token_callback, token):
        if verify_token_callback:
            return verify_token_callback(token)
        return False

    @staticmethod
    def get_authentication_from_headers():
        """ Returns (auth, token) """
        return request.headers.get(HTTPAUTH_AUTH_FIELD).split(None, 1)

    def authenticate_roles(self, verify_roles_callback, roles, required_roles):
        if verify_roles_callback:
            return verify_roles_callback(roles, required_roles=required_roles)
        return False

    def get_authorization_token(self, allow_access_token_parameter=False):

        # If token is unavailable, clearly state it in response to user
        token = "EMPTY"
        auth_type = None

        auth = request.authorization
        if auth is not None:
            # Basic authenticaton is now allowed
            return auth_type, token

        if HTTPAUTH_AUTH_FIELD in request.headers:
            # Flask/Werkzeug do not recognize any authentication types
            # other than Basic or Digest, so here we parse the header by hand
            try:
                auth_type, token = self.get_authentication_from_headers()
                return auth_type, token
            except ValueError:
                # The Authorization header is either empty or has no token
                pass

        if ALLOW_ACCESS_TOKEN_PARAMETER or allow_access_token_parameter:
            token = request.args.get("access_token")
            # We are assuming that received access token is always Bearer
            auth_type = 'Bearer'

        if token is None:
            auth_type = None
            return auth_type, token

        return auth_type, token

    def required(
            self, roles=[], required_roles=None, allow_access_token_parameter=False):
        # required_roles = 'all', 'any'
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Recover the auth object
                auth_type, token = self.get_authorization_token(
                    allow_access_token_parameter=allow_access_token_parameter)
                # Base header for errors
                headers = {HTTPAUTH_AUTH_HEADER: self.authenticate_header()}
                # Internal API 'self' reference
                decorated_self = Meta.get_self_reference_from_args(*args)

                if auth_type is None or auth_type.lower() != self._scheme.lower():
                    # Wrong authentication string
                    msg = (
                        "Missing credentials in headers, e.g. {}: '{} TOKEN'".format(
                            HTTPAUTH_AUTH_FIELD, HTTPAUTH_DEFAULT_SCHEME
                        )
                    )
                    log.info("Unauthorized request: missing credentials")
                    return decorated_self.force_response(
                        errors=msg,
                        code=hcodes.HTTP_BAD_UNAUTHORIZED,
                        headers=headers,
                    )

                # Handling OPTIONS forwarded to our application:
                # ignore headers and let go, avoid unwanted interactions with CORS
                if request.method != 'OPTIONS':

                    # Check authentication
                    token_fn = decorated_self.auth.verify_token
                    if not self.authenticate(token_fn, token):
                        # Clear TCP receive buffer of any pending data
                        log.verbose(request.data)
                        # Mimic the response from a normal endpoint
                        # To use the same standards
                        log.info("Invalid token received '{}'", token)
                        return decorated_self.force_response(
                            errors="Invalid token received",
                            code=hcodes.HTTP_BAD_UNAUTHORIZED,
                            headers=headers
                        )

                # Check roles
                if len(roles) > 0:
                    roles_fn = decorated_self.auth.verify_roles
                    if not self.authenticate_roles(roles_fn, roles, required_roles):
                        log.info("Unauthorized request: missing privileges")
                        return decorated_self.force_response(
                            errors="You are not authorized: missing privileges",
                            code=hcodes.HTTP_BAD_UNAUTHORIZED,
                        )

                return func(*args, **kwargs)

            return wrapper

        return decorator


authentication = HTTPTokenAuth()

log.info("{} authentication class initizialized", authentication.get_scheme())
