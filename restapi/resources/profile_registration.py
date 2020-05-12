# -*- coding: utf-8 -*-

from restapi.rest.definition import EndpointResource
from restapi import decorators
from restapi.exceptions import RestApiException
from restapi.services.detect import detector
from restapi.services.mail import send_mail, send_mail_is_active
from restapi.confs import get_project_configuration
from restapi.resources.profile_activation import send_activation_link

from restapi.utilities.logs import log


def notify_registration(user):
    if detector.get_bool_from_os("REGISTRATION_NOTIFICATIONS"):
        # Sending an email to the administrator
        title = get_project_configuration(
            "project.title", default='Unkown title'
        )
        subject = "{} New credentials requested".format(title)
        body = "New credentials request from {}".format(user.email)

        send_mail(body, subject)


class ProfileRegistration(EndpointResource):
    """ Current user informations """

    baseuri = "/auth"
    depends_on = ["not PROFILE_DISABLED"]
    labels = ["profile"]

    POST = {
        "/profile": {
            "summary": "Register new user",
            "custom_parameters": ["User"],
            "responses": {
                "200": {"description": "ID of new user"},
                "409": {"description": "This user already exists"},
                "503": {"description": "Server misconfiguration, password cannot be reset"},
            },
        }
    }

    @decorators.catch_errors()
    def post(self):
        """ Register new user """

        if not detector.get_bool_from_os("ALLOW_REGISTRATION"):  # pragma: no cover
            raise RestApiException(
                'Registration is not allowed',
                status_code=503,
            )

        if not send_mail_is_active():  # pragma: no cover
            log.error("Send mail is not active")
            raise RestApiException(
                {'Server misconfiguration': 'Registration is not allowed'},
                status_code=503,
            )

        v = self.get_input()
        if len(v) == 0:
            raise RestApiException('Empty input', status_code=400)

        if 'password' not in v:
            raise RestApiException(
                "Missing input: password", status_code=400
            )

        if 'email' not in v:
            raise RestApiException(
                "Missing input: email", status_code=400
            )

        if 'name' not in v:
            raise RestApiException(
                "Missing input: name", status_code=400
            )

        if 'surname' not in v:
            raise RestApiException(
                "Missing input: surname", status_code=400
            )

        user = self.auth.get_user_object(username=v['email'])
        if user is not None:
            raise RestApiException(
                "This user already exists: {}".format(v['email']),
                status_code=400,
            )

        v['is_active'] = False
        user = self.auth.create_user(v, [self.auth.default_role])

        try:
            self.auth.custom_post_handle_user_input(user, v)
            send_activation_link(self.auth, user)
            notify_registration(user)
            msg = (
                "We are sending an email to your email address where "
                "you will find the link to activate your account"
            )

        except BaseException as e:
            log.error("Errors during account registration: {}", str(e))
            user.delete()
            raise RestApiException(str(e))

        return self.response(msg)
