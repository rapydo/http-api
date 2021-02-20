from typing import Any, Dict, Union

from restapi import decorators
from restapi.config import get_project_configuration
from restapi.connectors import Connector, smtp
from restapi.endpoints.profile_activation import send_activation_link
from restapi.env import Env
from restapi.exceptions import Conflict, ServiceUnavailable
from restapi.models import Schema, fields, validate
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import DEFAULT_GROUP_NAME
from restapi.utilities.globals import mem

# from restapi.utilities.logs import log

# This endpoint requires the server to send the activation token via email
if Connector.check_availability("smtp"):

    auth = Connector.get_authentication_instance()

    # Note that these are callables returning a model, not models!
    # They will be executed a runtime
    def getInputSchema(request):

        # as defined in Marshmallow.schema.from_dict
        attributes: Dict[str, Union[fields.Field, type]] = {}

        attributes["name"] = fields.Str(required=True)
        attributes["surname"] = fields.Str(required=True)
        attributes["email"] = fields.Email(
            required=True, label="Username (email address)"
        )
        attributes["password"] = fields.Str(
            required=True,
            password=True,
            validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        )
        attributes["password_confirm"] = fields.Str(
            required=True,
            password=True,
            label="Password confirmation",
            validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        )

        if custom_fields := mem.customizer.get_custom_input_fields(
            request=None, scope=mem.customizer.REGISTRATION
        ):
            attributes.update(custom_fields)

        return Schema.from_dict(attributes, name="UserRegistration")

    class ProfileRegistration(EndpointResource):

        baseuri = "/auth"
        depends_on = ["MAIN_LOGIN_ENABLE", "ALLOW_REGISTRATION"]
        labels = ["profile"]

        @decorators.use_kwargs(getInputSchema)
        @decorators.endpoint(
            path="/profile",
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
                smtp_client = smtp.get_instance()
                if Env.get_bool("REGISTRATION_NOTIFICATIONS"):
                    # Sending an email to the administrator
                    title = get_project_configuration(
                        "project.title", default="Unkown title"
                    )
                    subject = f"{title} New credentials requested"
                    body = f"New credentials request from {user.email}"

                    smtp_client.send(body, subject)

                send_activation_link(smtp_client, self.auth, user)

            except BaseException as e:  # pragma: no cover
                self.auth.delete_user(user)
                raise ServiceUnavailable(f"Errors during account registration: {e}")

            return self.response(
                "We are sending an email to your email address where "
                "you will find the link to activate your account"
            )
