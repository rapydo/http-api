# -*- coding: utf-8 -*-
import os
import jwt

from restapi.rest.definition import EndpointResource
from restapi import decorators
from restapi.exceptions import RestApiException
from restapi.services.mail import send_mail
from restapi.confs import PRODUCTION, get_project_configuration
from restapi.utilities.templates import get_html_template

from restapi.utilities.logs import log


def send_activation_link(auth, user):

    title = get_project_configuration(
        "project.title", default='Unkown title'
    )

    activation_token, payload = auth.create_temporary_token(
        user, auth.ACTIVATE_ACCOUNT
    )

    domain = os.environ.get("DOMAIN")
    protocol = 'https' if PRODUCTION else 'http'

    rt = activation_token.replace(".", "+")
    log.debug("Activation token: {}", rt)
    url = "{}://{}/public/register/{}".format(protocol, domain, rt)
    body = "Follow this link to activate your account: {}".format(url)

    # customized template
    template_file = "activate_account.html"
    html_body = get_html_template(template_file, {"url": url})
    if html_body is None:
        html_body = body
        body = None

    default_subject = "{} account activation".format(title)
    subject = os.environ.get('EMAIL_ACTIVATION_SUBJECT', default_subject)

    sent = send_mail(html_body, subject, user.email, plain_body=body)
    if not sent:  # pragma: no cover
        raise BaseException("Error sending email, please retry")

    auth.save_token(
        user, activation_token, payload, token_type=auth.ACTIVATE_ACCOUNT)


class ProfileActivation(EndpointResource):
    depends_on = ["not PROFILE_DISABLED", "ALLOW_REGISTRATION"]
    baseuri = "/auth"
    labels = ["base", "profiles"]

    POST = {
        "/profile/activate": {
            "summary": "Ask a new activation link",
            "responses": {
                "200": {"description": "A new activation link has been sent"}
            },
        }
    }
    PUT = {
        "/profile/activate/<token>": {
            "summary": "Activate your account by providing the activation token",
            "responses": {
                "200": {"description": "Account successfully activated"}
            },
        }
    }

    @decorators.catch_errors()
    def put(self, token):

        token = token.replace("+", ".")
        try:
            # Unpack and verify token. If ok, self.auth will be added with
            # auth._user auth._token and auth._jti
            valid = self.auth.verify_token(
                token, raiseErrors=True, token_type=self.auth.ACTIVATE_ACCOUNT
            )
            if not valid:
                raise RestApiException("Invalid activation token", status_code=403)

        # If token is expired
        except jwt.exceptions.ExpiredSignatureError:
            raise RestApiException(
                'Invalid activation token: this request is expired',
                status_code=400,
            )

        # if token is not yet active
        except jwt.exceptions.ImmatureSignatureError:
            raise RestApiException(
                'Invalid activation token', status_code=400
            )

        # if token does not exist (or other generic errors)
        except Exception:
            raise RestApiException(
                'Invalid activation token', status_code=400
            )

        # Recovering token object from jti
        token = self.auth.get_tokens(token_jti=self.auth._jti)
        if len(token) == 0:
            raise RestApiException(
                'Invalid activation token: this request is no longer valid',
                status_code=400,
            )

        # If user logged is already active, invalidate the token
        if self.auth._user.is_active is not None and self.auth._user.is_active:
            self.auth.invalidate_token(token)
            raise RestApiException(
                'Invalid activation token: this request is no longer valid',
                status_code=400,
            )

        # The activation token is valid, do something
        self.auth._user.is_active = True
        self.auth.save_user(self.auth._user)

        # Bye bye token (reset activation are valid only once)
        self.auth.invalidate_token(token)

        return self.response("Account activated")

    @decorators.catch_errors()
    def post(self):

        v = self.get_input()
        if len(v) == 0:
            raise RestApiException('Empty input', status_code=400)

        if 'username' not in v:
            raise RestApiException(
                'Missing required input: username', status_code=400
            )

        user = self.auth.get_user_object(username=v['username'])

        # if user is None this endpoint does nothing and the response
        # remain the same (we are sending an email bla bla)
        # => security to avoid user guessing
        if user is not None:
            send_activation_link(self.auth, user)
        msg = (
            "We are sending an email to your email address where "
            "you will find the link to activate your account"
        )
        return self.response(msg)
