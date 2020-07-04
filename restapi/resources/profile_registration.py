from flask_apispec import MethodResource, use_kwargs
from marshmallow import fields, validate

from restapi import decorators
from restapi.confs import get_project_configuration
from restapi.env import Env
from restapi.exceptions import Conflict, RestApiException
from restapi.models import InputSchema
from restapi.resources.profile_activation import send_activation_link
from restapi.rest.definition import EndpointResource
from restapi.services.mail import send_mail, send_mail_is_active

# This endpoint require the server to send the activation oken via email
if send_mail_is_active():

    auth = EndpointResource.load_authentication()

    class User(InputSchema):
        email = fields.Email(required=True)
        name = fields.Str(required=True)
        surname = fields.Str(required=True)
        password = fields.Str(
            required=True,
            password=True,
            validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        )
        password_confirm = fields.Str(
            required=True,
            password=True,
            validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        )

    class ProfileRegistration(MethodResource, EndpointResource):
        """ Current user informations """

        baseuri = "/auth"
        depends_on = ["not PROFILE_DISABLED", "ALLOW_REGISTRATION"]
        labels = ["profile"]

        _POST = {
            "/profile": {
                "summary": "Register new user",
                "responses": {
                    "200": {"description": "ID of new user"},
                    "409": {"description": "This user already exists"},
                },
            }
        }

        @decorators.catch_errors()
        @use_kwargs(User)
        def post(self, **kwargs):
            """ Register new user """

            email = kwargs.get("email")
            user = self.auth.get_user_object(username=email)
            if user is not None:
                raise Conflict(f"This user already exists: {email}")

            if kwargs.get("password") != kwargs.get("password_confirm"):
                raise Conflict("Your password doesn't match the confirmation")

            if self.auth.VERIFY_PASSWORD_STRENGTH:

                check, msg = self.auth.verify_password_strength(
                    kwargs.get("password"), None
                )

                if not check:
                    raise Conflict(msg)

            kwargs["is_active"] = False
            user = self.auth.create_user(kwargs, [self.auth.default_role])

            try:
                self.auth.custom_post_handle_user_input(user, kwargs)

                if Env.get_bool("REGISTRATION_NOTIFICATIONS"):
                    # Sending an email to the administrator
                    title = get_project_configuration(
                        "project.title", default="Unkown title"
                    )
                    subject = f"{title} New credentials requested"
                    body = f"New credentials request from {user.email}"

                    send_mail(body, subject)

                send_activation_link(self.auth, user)

            except BaseException as e:
                user.delete()
                raise RestApiException(f"Errors during account registration: {e}")

            return self.response(
                "We are sending an email to your email address where "
                "you will find the link to activate your account"
            )
