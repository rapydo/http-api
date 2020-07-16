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

from restapi.env import Env
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

HTTPAUTH_SCHEME = "Bearer"
HTTPAUTH_AUTH_FIELD = "Authorization"
# Base header for errors
HTTPAUTH_ERR_HEADER = {
    "WWW-Authenticate": f'{HTTPAUTH_SCHEME} realm="Authentication Required"'
}
ALLOW_ACCESS_TOKEN_PARAMETER = Env.get_bool("ALLOW_ACCESS_TOKEN_PARAMETER")


class HTTPTokenAuth:
    """
    A class to implement a Generic Token (oauth2-like) authentication.
    Started on a draft of the great miguel: http://bit.ly/2nTqQKA
    """

    @staticmethod
    def get_authorization_token(allow_access_token_parameter=False):
        # Basic authenticaton is now allowed
        if request.authorization is not None:
            return None, None

        if HTTPAUTH_AUTH_FIELD in request.headers:
            # Flask/Werkzeug do not recognize any authentication types
            # other than Basic or Digest, so here we parse the header by hand
            try:
                auth_header = request.headers.get(HTTPAUTH_AUTH_FIELD)
                # Do not return directly auth_header.split
                # Otherwise in case of malformed tokens the exception will be raised
                # outside this function and probably not properly catched
                # e.g. {'Authorization': 'Bearer'}  # no token provided
                # will raise not enough values to unpack (expected 2, got 1)
                auth_type, token = auth_header.split(None, 1)
                return auth_type, token
            except ValueError:
                # The Authorization header is either empty or has no token
                return None, None

        elif ALLOW_ACCESS_TOKEN_PARAMETER or allow_access_token_parameter:
            token = request.args.get("access_token")

            if token is None:
                return None, None
            return HTTPAUTH_SCHEME, token

        return None, None

    # Deprecated since 0.7.5
    @staticmethod
    def required(
        roles=None, required_roles=None, allow_access_token_parameter=False
    ):  # pragma: no cover
        log.warning(
            "Deprecated use of auth.required decorator, "
            "use require/require_all/require_any"
        )

        return HTTPTokenAuth.require(
            roles=roles,
            required_roles=required_roles,
            allow_access_token_parameter=allow_access_token_parameter,
        )

    @staticmethod
    def require_all(*arg, allow_access_token_parameter=False):
        return HTTPTokenAuth.require(
            roles=arg,
            required_roles="all",
            allow_access_token_parameter=allow_access_token_parameter,
        )

    @staticmethod
    def require_any(*arg, allow_access_token_parameter=False):
        return HTTPTokenAuth.require(
            roles=arg,
            required_roles="any",
            allow_access_token_parameter=allow_access_token_parameter,
        )

    @staticmethod
    def require(roles=None, required_roles=None, allow_access_token_parameter=False):
        # required_roles = 'all', 'any'
        def decorator(func):
            # it is used in Customization to verify if an endpoint is requiring
            # authentication and inject 401 errors
            func.__dict__["auth.required"] = True

            @wraps(func)
            def wrapper(*args, **kwargs):
                # Recover the auth object
                auth_type, token = HTTPTokenAuth.get_authorization_token(
                    allow_access_token_parameter=allow_access_token_parameter
                )

                # Internal API 'self' reference
                caller = Meta.get_self_reference_from_args(*args)

                if auth_type is None or auth_type != HTTPAUTH_SCHEME:
                    # Wrong authentication string
                    msg = (
                        "Missing credentials in headers"
                        f", e.g. {HTTPAUTH_AUTH_FIELD}: '{HTTPAUTH_SCHEME} TOKEN'"
                    )
                    log.debug("Unauthorized request: missing credentials")
                    return caller.response(msg, code=401, headers=HTTPAUTH_ERR_HEADER)

                # Handling OPTIONS forwarded to our application:
                # ignore headers and let go, avoid unwanted interactions with CORS
                if request.method != "OPTIONS":

                    caller.unpacked_token = caller.auth.verify_token(token)
                    # Check authentication
                    if not caller.unpacked_token[0]:
                        # Clear TCP receive buffer of any pending data
                        log.verbose(request.data)
                        # Mimic the response from a normal endpoint
                        # To use the same standards
                        # log.info("Invalid token received '{}'", token)
                        log.debug("Invalid token received")
                        return caller.response(
                            "Invalid token received",
                            headers=HTTPAUTH_ERR_HEADER,
                            code=401,
                        )

                # Check roles
                if not caller.auth.verify_roles(
                    caller.unpacked_token[3], roles, required_roles=required_roles
                ):
                    log.info("Unauthorized request: missing privileges")
                    return caller.response(
                        "You are not authorized: missing privileges", code=401,
                    )

                return func(*args, **kwargs)

            return wrapper

        return decorator
