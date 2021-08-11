from jwt.exceptions import ExpiredSignatureError, ImmatureSignatureError

from restapi import decorators
from restapi.config import get_frontend_url
from restapi.connectors import Connector
from restapi.connectors.smtp.notifications import send_activation_link
from restapi.exceptions import BadRequest, ServiceUnavailable
from restapi.models import fields
from restapi.rest.definition import EndpointResource, Response

# from restapi.utilities.logs import log


class ProfileActivation(EndpointResource):
    depends_on = ["MAIN_LOGIN_ENABLE", "ALLOW_REGISTRATION", "AUTH_ENABLE"]
    labels = ["base", "profile"]

    @decorators.endpoint(
        path="/auth/profile/activate/<token>",
        summary="Activate your account by providing the activation token",
        responses={200: "Account successfully activated", 400: "Invalid token"},
    )
    def put(self, token: str) -> Response:

        token = token.replace("%2B", ".")
        token = token.replace("+", ".")

        try:
            # valid, token, jti, user
            _, _, jti, user = self.auth.verify_token(
                token, raiseErrors=True, token_type=self.auth.ACTIVATE_ACCOUNT
            )

        # If token is expired
        except ExpiredSignatureError:
            raise BadRequest(
                "Invalid activation token: this request is expired",
            )

        # if token is not active yet
        except ImmatureSignatureError:
            raise BadRequest("Invalid activation token")

        # if token does not exist (or other generic errors)
        except Exception:
            raise BadRequest("Invalid activation token")

        if user is None:  # pragma: no cover
            raise BadRequest("Invalid activation token")

        self.auth.verify_blocked_username(user.email)

        # Recovering token object from jti
        token_obj = self.auth.get_tokens(token_jti=jti)
        # Cannot be tested, this is an extra test to prevent any unauthorized access...
        # but invalid tokens are already refused above, with auth.verify_token
        if len(token_obj) == 0:  # pragma: no cover
            raise BadRequest(
                "Invalid activation token: this request is no longer valid"
            )

        # If user logged is already active, invalidate the token
        if user.is_active:
            self.auth.invalidate_token(token)
            raise BadRequest(
                "Invalid activation token: this request is no longer valid"
            )

        # The activation token is valid, do something
        user.is_active = True
        self.auth.save_user(user)

        # Bye bye token (activation tokens are valid only once)
        self.auth.invalidate_token(token)

        self.log_event(self.events.activation, user=user, target=user)

        return self.response("Account activated")

    @decorators.use_kwargs({"username": fields.Email(required=True)})
    @decorators.endpoint(
        path="/auth/profile/activate",
        summary="Ask a new activation link",
        responses={200: "A new activation link has been sent"},
    )
    def post(self, username: str) -> Response:

        self.auth.verify_blocked_username(username)

        user = self.auth.get_user(username=username)

        # if user is None this endpoint does nothing but the response
        # remain the same to prevent any user guessing
        if user is not None:

            auth = Connector.get_authentication_instance()

            activation_token, payload = auth.create_temporary_token(
                user, auth.ACTIVATE_ACCOUNT
            )

            server_url = get_frontend_url()

            rt = activation_token.replace(".", "+")
            url = f"{server_url}/public/register/{rt}"

            sent = send_activation_link(user, url)

            if not sent:  # pragma: no cover
                raise ServiceUnavailable("Error sending email, please retry")

            auth.save_token(
                user, activation_token, payload, token_type=auth.ACTIVATE_ACCOUNT
            )

        msg = (
            "We are sending an email to your email address where "
            "you will find the link to activate your account"
        )
        return self.response(msg)
