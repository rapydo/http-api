from restapi import decorators
from restapi.confs import get_project_configuration
from restapi.endpoints.profile_activation import send_activation_link
from restapi.env import Env
from restapi.exceptions import Conflict, RestApiException
from restapi.models import Schema, fields, validate
from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector

# This endpoint require the server to send the activation oken via email
if detector.check_availability("smtp"):

    auth = EndpointResource.load_authentication()

    class User(Schema):
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

    class ProfileRegistration(EndpointResource):
        """ Current user informations """

        baseuri = "/auth"
        depends_on = ["not PROFILE_DISABLED", "ALLOW_REGISTRATION"]
        labels = ["profile"]

        @decorators.use_kwargs(User)
        @decorators.endpoint(
            path="/profile",
            summary="Register new user",
            responses={
                200: "The uuid of the new user is returned",
                409: "This user already exists",
            },
        )
        def post(self, **kwargs):
            """ Register new user """

            email = kwargs.get("email")
            user = self.auth.get_user_object(username=email)
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

            userdata, extra_userdata = self.auth.custom_user_properties_pre(kwargs)

            userdata["is_active"] = False
            user = self.auth.create_user(userdata, [self.auth.default_role])

            try:
                self.auth.custom_user_properties_post(
                    user, userdata, extra_userdata, self.auth.db
                )

                smtp = self.get_service_instance("smtp")
                if Env.get_bool("REGISTRATION_NOTIFICATIONS"):
                    # Sending an email to the administrator
                    title = get_project_configuration(
                        "project.title", default="Unkown title"
                    )
                    subject = f"{title} New credentials requested"
                    body = f"New credentials request from {user.email}"

                    smtp.send(body, subject)

                send_activation_link(smtp, self.auth, user)

            except BaseException as e:
                user.delete()
                raise RestApiException(f"Errors during account registration: {e}")

            return self.response(
                "We are sending an email to your email address where "
                "you will find the link to activate your account"
            )
