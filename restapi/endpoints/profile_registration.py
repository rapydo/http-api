from typing import Any

from restapi import decorators
from restapi.connectors import Connector
from restapi.connectors.smtp.notifications import (
    send_activation_link,
    send_registration_notification,
)
from restapi.endpoints.schemas import user_registration_input
from restapi.env import Env
from restapi.exceptions import Conflict, ServiceUnavailable
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import DEFAULT_GROUP_NAME

# from restapi.utilities.logs import log

# This endpoint needs to send the activation token via email
if Connector.check_availability("smtp"):

    class ProfileRegistration(EndpointResource):

        depends_on = ["MAIN_LOGIN_ENABLE", "ALLOW_REGISTRATION"]
        labels = ["profile"]

        @decorators.use_kwargs(user_registration_input)
        @decorators.endpoint(
            path="/auth/profile",
            summary="Register new user",
            responses={
                200: "The uuid of the new user is returned",
                409: "This user already exists",
            },
        )
        def post(self, **kwargs: Any) -> Response:
            """ Register new user """

            email = kwargs.get("email")
            user = self.auth.get_user(username=email)
            if user is not None:
                raise Conflict(f"This user already exists: {email}")

            password_confirm = kwargs.pop("password_confirm")
            if kwargs.get("password") != password_confirm:
                raise Conflict("Your password doesn't match the confirmation")

            if self.auth.VERIFY_PASSWORD_STRENGTH:

                check, msg = self.auth.verify_password_strength(
                    kwargs.get("password"), None
                )

                if not check:
                    raise Conflict(msg)

            kwargs["is_active"] = False
            user = self.auth.create_user(kwargs, [self.auth.default_role])

            default_group = self.auth.get_group(name=DEFAULT_GROUP_NAME)
            self.auth.add_user_to_group(user, default_group)
            self.auth.save_user(user)

            self.log_event(self.events.create, user, kwargs)

            try:
                # Sending an email to the administrator
                if Env.get_bool("REGISTRATION_NOTIFICATIONS"):
                    send_registration_notification(user.email)

                send_activation_link(user)

            except BaseException as e:  # pragma: no cover
                self.auth.delete_user(user)
                raise ServiceUnavailable(f"Errors during account registration: {e}")

            return self.response(
                "We are sending an email to your email address where "
                "you will find the link to activate your account"
            )
