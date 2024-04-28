"""
The tokens used are RFC6750 Bearer tokens.

The Resource should validate the tokens using the token validation endpoint;
its basic use is by adding
'Authorization: Bearer ' + tokenString to the HTTP header;
cf. RFC6749 section 7.1.

Note that anyone can validate a token as it is a bearer token:
there is no client id nor is client authentication required.
"""

from collections.abc import Iterable
from functools import wraps
from typing import Any, Callable, Optional, Union, cast

from flask import request
from werkzeug.datastructures import Authorization

from restapi.customizer import FlaskRequest
from restapi.env import Env
from restapi.services.authentication import (
    ALL_ROLES,
    ANY_ROLE,
    BaseAuthentication,
    Role,
)
from restapi.types import EndpointFunction
from restapi.utilities import print_and_exit
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

HTTPAUTH_SCHEME = "bearer"
HTTPAUTH_AUTH_FIELD = "Authorization"
# Base header for errors
HTTPAUTH_ERR_HEADER = {
    "WWW-Authenticate": f'{HTTPAUTH_SCHEME} realm="Authentication Required"'
}
ALLOW_ACCESS_TOKEN_PARAMETER = Env.get_bool("ALLOW_ACCESS_TOKEN_PARAMETER")
TOKEN_VALIDATED_KEY = "TOKEN_VALIDATED"


class HTTPTokenAuth:
    @staticmethod
    def get_authorization_token(
        allow_access_token_parameter: bool = False,
    ) -> tuple[Optional[str], Optional[str]]:
        if request.authorization is not None:
            auth_type = request.authorization.type
            token = request.authorization.token
            return auth_type, token
        elif HTTPAUTH_AUTH_FIELD in request.headers:
            parsed_auth_header = Authorization.from_header(
                request.headers.get(HTTPAUTH_AUTH_FIELD)
            )
            if parsed_auth_header is None:
                return None, None
            auth_type = parsed_auth_header.type
            token = parsed_auth_header.token
        elif ALLOW_ACCESS_TOKEN_PARAMETER or allow_access_token_parameter:
            if not (token := request.args.get("access_token", "")):
                return None, None
            return HTTPAUTH_SCHEME, token
        return None, None

    @staticmethod
    def is_session_user_admin(request: FlaskRequest, auth: BaseAuthentication) -> bool:
        if not request:
            return False

        _, token = HTTPTokenAuth.get_authorization_token(
            allow_access_token_parameter=False
        )
        _, _, _, user = auth.verify_token(token)

        return auth.is_admin(user)

    @staticmethod
    def optional(
        allow_access_token_parameter: bool = False,
    ) -> Callable[[EndpointFunction], EndpointFunction]:
        def decorator(func: EndpointFunction) -> EndpointFunction:
            # it is used in Loader to verify if an endpoint is requiring
            # authentication and inject 401 errors
            func.__dict__["auth.optional"] = True

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Recover the auth object
                auth_type, token = HTTPTokenAuth.get_authorization_token(
                    allow_access_token_parameter=allow_access_token_parameter
                )

                # Internal API 'self' reference
                caller = Meta.get_self_reference_from_args(*args)

                if caller is None:  # pragma: no cover
                    # An exit here is really really dangerous, but even if
                    # get_self_reference_from_args can return None, this case is quite
                    # impossible... however with None the server can't continue!
                    print_and_exit(
                        "Server misconfiguration, self reference can't be None!"
                    )

                if (
                    auth_type is not None
                    and auth_type == HTTPAUTH_SCHEME
                    and request.method != "OPTIONS"
                ):
                    # valid, token, jti, user
                    valid, token, _, user = caller.auth.verify_token(token)

                    # Check authentication. Optional authentication is valid if:
                    # 1) token is missing
                    # 2) token is valid
                    # Invalid tokens are rejected
                    if not valid:
                        # Clear TCP receive buffer of any pending data
                        _ = request.data
                        # Mimic the response from a normal endpoint
                        # To use the same standards
                        # log.info("Invalid token received '{}'", token)
                        log.debug("Invalid token received")
                        return caller.response(
                            "Invalid token received",
                            headers=HTTPAUTH_ERR_HEADER,
                            code=401,
                            allow_html=True,
                        )

                    caller.authorized_user = user.uuid
                    kwargs["user"] = user
                    request.environ[TOKEN_VALIDATED_KEY] = True
                else:
                    kwargs["user"] = None

                return func(*args, **kwargs)

            return cast(EndpointFunction, wrapper)

        return decorator

    @classmethod
    def require_all(
        cls,
        *roles: Union[str, Role],
        allow_access_token_parameter: bool = False,
    ) -> Callable[[EndpointFunction], EndpointFunction]:
        return cls.require(
            roles=roles,
            required_roles=ALL_ROLES,
            allow_access_token_parameter=allow_access_token_parameter,
        )

    @classmethod
    def require_any(
        cls,
        *roles: Union[str, Role],
        allow_access_token_parameter: bool = False,
    ) -> Callable[[EndpointFunction], EndpointFunction]:
        return cls.require(
            roles=roles,
            required_roles=ANY_ROLE,
            allow_access_token_parameter=allow_access_token_parameter,
        )

    @classmethod
    def require(
        cls,
        roles: Optional[Iterable[Union[str, Role]]] = None,
        required_roles: str = ALL_ROLES,
        allow_access_token_parameter: bool = False,
    ) -> Callable[[EndpointFunction], EndpointFunction]:
        def decorator(func: EndpointFunction) -> EndpointFunction:
            # it is used in Loader to verify if an endpoint is requiring
            # authentication and inject 401 errors
            func.__dict__["auth.required"] = True

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Recover the auth object
                auth_type, token = HTTPTokenAuth.get_authorization_token(
                    allow_access_token_parameter=allow_access_token_parameter
                )

                # Internal API 'self' reference
                caller = Meta.get_self_reference_from_args(*args)

                if caller is None:  # pragma: no cover
                    # An exit here is really really dangerous, but even if
                    # get_self_reference_from_args can return None, this case is quite
                    # impossible... however with None the server can't continue!
                    print_and_exit(
                        "Server misconfiguration, self reference can't be None!"
                    )

                if auth_type is None or auth_type != HTTPAUTH_SCHEME:
                    # Wrong authentication string
                    msg = (
                        "Missing credentials in headers"
                        f", e.g. {HTTPAUTH_AUTH_FIELD}: '{HTTPAUTH_SCHEME} TOKEN'"
                    )
                    log.debug("Unauthorized request: missing credentials")
                    return caller.response(
                        msg, code=401, headers=HTTPAUTH_ERR_HEADER, allow_html=True
                    )

                # Handling OPTIONS forwarded to our application:
                # ignore headers and let go, avoid unwanted interactions with CORS
                if request.method != "OPTIONS":
                    # valid, token, jti, user
                    valid, token, _, user = caller.auth.verify_token(token)
                    # Check authentication
                    if not valid:
                        # Clear TCP receive buffer of any pending data
                        _ = request.data
                        # Mimic the response from a normal endpoint
                        # To use the same standards
                        # log.info("Invalid token received '{}'", token)
                        log.debug("Invalid token received")
                        return caller.response(
                            "Invalid token received",
                            headers=HTTPAUTH_ERR_HEADER,
                            code=401,
                            allow_html=True,
                        )
                    request.environ[TOKEN_VALIDATED_KEY] = True

                # Check roles
                if not caller.auth.verify_roles(
                    user, roles, required_roles=required_roles
                ):
                    log.info("Unauthorized request: missing privileges.")
                    return caller.response(
                        "You are not authorized: missing privileges",
                        code=401,
                        allow_html=True,
                    )

                caller.authorized_user = user.uuid
                kwargs["user"] = user
                return func(*args, **kwargs)

            return cast(EndpointFunction, wrapper)

        return decorator
