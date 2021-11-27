"""
This endpoint validates an UNLOCK token to re-enable credentials
after a block due to too many failed attemps.
Unlock URL (including token) is sent by email
"""
from jwt.exceptions import ExpiredSignatureError, ImmatureSignatureError

from restapi import decorators
from restapi.exceptions import BadRequest
from restapi.rest.definition import EndpointResource, Response
from restapi.utilities.logs import log


class LoginUnlock(EndpointResource):
    depends_on = ["AUTH_MAX_LOGIN_ATTEMPTS", "AUTH_ENABLE"]

    @decorators.endpoint(
        path="/auth/login/unlock/<token>",
        summary="Unlock credentials after a login block",
        description="The unlock sent by email is validated here to restore credentials",
        responses={
            200: "Credentials are now unlocked",
            400: "Invalid token",
        },
    )
    def post(self, token: str) -> Response:

        token = token.replace("%2B", ".")
        token = token.replace("+", ".")

        try:
            # valid, token, jti, user
            _, _, jti, user = self.auth.verify_token(
                token, raiseErrors=True, token_type=self.auth.UNLOCK_CREDENTIALS
            )

        # If token is expired
        except ExpiredSignatureError:
            raise BadRequest(
                "Invalid unlock token: this request is expired",
            )

        # if token is not active yet
        except ImmatureSignatureError:
            raise BadRequest("Invalid unlock token")

        # if token does not exist (or other generic errors)
        except Exception:
            raise BadRequest("Invalid unlock token")

        if user is None:  # pragma: no cover
            raise BadRequest("Invalid unlock token")

        # Recovering token object from jti
        token_obj = self.auth.get_tokens(token_jti=jti)
        # Cannot be tested, this is an extra test to prevent any unauthorized access...
        # but invalid tokens are already refused above, with auth.verify_token
        if len(token_obj) == 0:  # pragma: no cover
            raise BadRequest("Invalid unlock token: this request is no longer valid")

        # If credentials are no longer locked, invalidate the token
        if self.auth.count_failed_login(user.email) < self.auth.MAX_LOGIN_ATTEMPTS:
            self.auth.invalidate_token(token)
            raise BadRequest("Invalid unlock token: this request is no longer valid")

        # The unlock token is valid, do something
        self.auth.flush_failed_logins(user.email)
        log.info(
            "{} provided a valid unlock token and credentials block is now revoked",
            user.email,
        )

        # Bye bye token (unlock tokens are valid only once)
        self.auth.invalidate_token(token)

        self.log_event(self.events.login_unlock, user=user, target=user)

        return self.response("Credentials unlocked")
