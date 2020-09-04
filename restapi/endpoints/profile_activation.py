import os

import jwt

from restapi import decorators
from restapi.confs import get_frontend_url, get_project_configuration
from restapi.exceptions import RestApiException
from restapi.models import fields
from restapi.rest.definition import EndpointResource
from restapi.utilities.logs import log
from restapi.utilities.templates import get_html_template


def send_activation_link(smtp, auth, user):

    title = get_project_configuration("project.title", default="Unkown title")

    activation_token, payload = auth.create_temporary_token(user, auth.ACTIVATE_ACCOUNT)

    server_url = get_frontend_url()

    rt = activation_token.replace(".", "+")
    log.debug("Activation token: {}", rt)
    url = f"{server_url}/public/register/{rt}"
    body = f"Follow this link to activate your account: {url}"

    # customized template
    template_file = "activate_account.html"
    html_body = get_html_template(template_file, {"url": url})
    if html_body is None:
        html_body = body
        body = None

    default_subject = f"{title} account activation"
    subject = os.getenv("EMAIL_ACTIVATION_SUBJECT", default_subject)

    sent = smtp.send(html_body, subject, user.email, plain_body=body)
    if not sent:  # pragma: no cover
        raise BaseException("Error sending email, please retry")

    auth.save_token(user, activation_token, payload, token_type=auth.ACTIVATE_ACCOUNT)


class ProfileActivation(EndpointResource):
    depends_on = ["not PROFILE_DISABLED", "ALLOW_REGISTRATION"]
    baseuri = "/auth"
    labels = ["base", "profiles"]

    @decorators.endpoint(
        path="/profile/activate/<token>",
        summary="Activate your account by providing the activation token",
        responses={200: "Account successfully activated"},
    )
    def put(self, token):

        token = token.replace("%2B", ".")
        token = token.replace("+", ".")
        try:
            unpacked_token = self.auth.verify_token(
                token, raiseErrors=True, token_type=self.auth.ACTIVATE_ACCOUNT
            )

        # If token is expired
        except jwt.exceptions.ExpiredSignatureError:
            raise RestApiException(
                "Invalid activation token: this request is expired", status_code=400,
            )

        # if token is not yet active
        except jwt.exceptions.ImmatureSignatureError:
            raise RestApiException("Invalid activation token", status_code=400)

        # if token does not exist (or other generic errors)
        except BaseException:
            raise RestApiException("Invalid activation token", status_code=400)

        # Recovering token object from jti
        jti = unpacked_token[2]
        token_obj = self.auth.get_tokens(token_jti=jti)
        # Cannot be tested, this is an extra test to prevent any unauthorized access...
        # but invalid tokens are already refused above, with auth.verify_token
        if len(token_obj) == 0:  # pragma: no cover
            raise RestApiException(
                "Invalid activation token: this request is no longer valid",
                status_code=400,
            )

        user = unpacked_token[3]
        # If user logged is already active, invalidate the token
        if user.is_active:
            self.auth.invalidate_token(token)
            raise RestApiException(
                "Invalid activation token: this request is no longer valid",
                status_code=400,
            )

        # The activation token is valid, do something
        user.is_active = True
        self.auth.save_user(user)

        # Bye bye token (activation tokens are valid only once)
        self.auth.invalidate_token(token)

        return self.response("Account activated")

    @decorators.use_kwargs({"username": fields.Email(required=True)})
    @decorators.endpoint(
        path="/profile/activate",
        summary="Ask a new activation link",
        responses={200: "A new activation link has been sent"},
    )
    def post(self, username):

        user = self.auth.get_user_object(username=username)

        # if user is None this endpoint does nothing but the response
        # remain the same to prevent any user guessing
        if user is not None:
            smtp = self.get_service_instance("smtp")
            send_activation_link(smtp, self.auth, user)
        msg = (
            "We are sending an email to your email address where "
            "you will find the link to activate your account"
        )
        return self.response(msg)
