# -*- coding: utf-8 -*-

import os
import jwt
import pytz
from glom import glom

from restapi.rest.definition import EndpointResource
from restapi import decorators as decorate
from restapi.exceptions import RestApiException
from restapi.services.detect import detector
from restapi.services.mail import send_mail, send_mail_is_active
from restapi.confs import PRODUCTION
from restapi.services.mail import get_html_template
from restapi.flask_ext.flask_auth import HandleSecurity

from utilities.globals import mem
from utilities import htmlcodes as hcodes
from utilities.time import timestamp_from_string
from utilities.meta import Meta
from utilities.logs import get_logger

log = get_logger(__name__)
meta = Meta()

"""
class Profile
    GET: Current user informations
    POST: Create new user (registration)
    PUT: Update profile for current user

class ProfileActivate
    PUT: active profile (user clicked the activation link)
    POST: request activation link

class RecoverPassword
    POST: request reset link
    PUT: set new password (user clicked the reset link)

"""


def send_activation_link(auth, user):

    title = glom(
        mem.customizer._configurations, "project.title", default='Unkown title'
    )

    activation_token, jti = auth.create_reset_token(user, auth.ACTIVATE_ACCOUNT)

    domain = os.environ.get("DOMAIN")
    if PRODUCTION:
        protocol = "https"
    else:
        protocol = "http"

    rt = activation_token.replace(".", "+")
    log.debug("Activation token: %s" % rt)
    url = "%s://%s/public/register/%s" % (protocol, domain, rt)
    body = "Follow this link to activate your account: %s" % url

    obj = meta.get_customizer_class('apis.profile', 'CustomActivation')

    # NORMAL ACTIVATION
    if obj is None:

        # customized template
        template_file = "activate_account.html"
        html_body = get_html_template(template_file, {"url": url})
        if html_body is None:
            html_body = body
            body = None

        # NOTE: possibility to define a different subject
        default_subject = "%s account activation" % title
        subject = os.environ.get('EMAIL_ACTIVATION_SUBJECT', default_subject)

        sent = send_mail(html_body, subject, user.email, plain_body=body)
        if not sent:
            raise BaseException("Error sending email, please retry")

    # EXTERNAL SMTP/EMAIL SENDER
    else:
        try:
            obj.request_activation(name=user.name, email=user.email, url=url)
        except BaseException as e:
            log.error(
                "Could not send email with custom service:\n%s: %s",
                e.__class__.__name__,
                e,
            )
            raise

    auth.save_token(user, activation_token, jti, token_type=auth.ACTIVATE_ACCOUNT)


def notify_registration(user):
    var = "REGISTRATION_NOTIFICATIONS"
    if detector.get_bool_from_os(var):
        # Sending an email to the administrator
        title = glom(
            mem.customizer._configurations, "project.title", default='Unkown title'
        )
        subject = "%s New credentials requested" % title
        body = "New credentials request from %s" % user.email

        send_mail(body, subject)


def custom_extra_registration(variables):
    # Add the possibility to user a custom registration extra service
    oscr = detector.get_global_var('CUSTOM_REGISTER', default='noname')
    obj = meta.get_customizer_class(
        'apis.profile', 'CustomRegister', {'client_name': oscr}
    )
    if obj is not None:
        try:
            obj.new_member(
                email=variables['email'],
                name=variables['name'],
                surname=variables['surname'],
            )
        except BaseException as e:
            log.error(
                "Could not register your custom profile:\n%s: %s",
                e.__class__.__name__,
                e,
            )


class Profile(EndpointResource):
    """ Current user informations """
    baseuri = "/auth"
    depends_on = ["not PROFILE_DISABLED"]
    labels = ["profiles"]

    SPECS = {
        "mapping": {
            "whoami": "/profile"
        }
    }
    GET = {
        "whoami": {
            "summary": "List profile attributes",
            "custom": {
                "authentication": True
            },
            "responses": {
                "200": {
                    "description": "Dictionary with all profile attributes"
                }
            }
        }
    }
    POST = {
        "whoami": {
            "summary": "Register new user",
            "custom": {
                "authentication": False
            },
            "custom_parameters": [
                "User"
            ],
            "responses": {
                "200": {
                    "description": "ID of new user"
                }
            }
        }
    }
    PUT = {
        "whoami": {
            "summary": "Update profile attributes",
            "custom": {
                "authentication": True
            },
            "parameters": [
                {
                    "name": "credentials",
                    "in": "body",
                    "schema": {
                        "$ref": "#/definitions/ProfileUpdate"
                    }
                }
            ],
            "responses": {
                "204": {
                    "description": "Updated has been successful"
                }
            }
        }
    }

    def get(self):

        current_user = self.get_current_user()
        data = {
            'uuid': current_user.uuid,
            'status': "Valid user",
            'email': current_user.email,
        }

        # roles = []
        roles = {}
        for role in current_user.roles:
            # roles.append(role.name)
            roles[role.name] = role.description
        data["roles"] = roles

        try:
            for g in current_user.belongs_to.all():
                data["group"] = {
                    "uuid": g.uuid,
                    "shortname": g.shortname,
                    "fullname": g.fullname,
                }
        except BaseException as e:
            log.verbose(e)

        data["isAdmin"] = self.auth.verify_admin()
        data["isLocalAdmin"] = self.auth.verify_local_admin()

        if hasattr(current_user, 'privacy_accepted'):
            data["privacy_accepted"] = current_user.privacy_accepted

        if hasattr(current_user, 'name'):
            data["name"] = current_user.name

        if hasattr(current_user, 'surname'):
            data["surname"] = current_user.surname

        if self.auth.SECOND_FACTOR_AUTHENTICATION is not None:
            data['2fa'] = self.auth.SECOND_FACTOR_AUTHENTICATION

        obj = meta.get_customizer_class('apis.profile', 'CustomProfile')
        if obj is not None:
            try:
                data = obj.manipulate(ref=self, user=current_user, data=data)
            except BaseException as e:
                log.error("Could not custom manipulate profile:\n%s", e)

        return data

    @decorate.catch_error()
    def post(self):
        """ Register new user """

        if not send_mail_is_active():
            raise RestApiException(
                'Server misconfiguration, unable to reset password. '
                + 'Please report this error to adminstrators',
                status_code=hcodes.HTTP_BAD_REQUEST,
            )

        v = self.get_input()
        if len(v) == 0:
            raise RestApiException('Empty input', status_code=hcodes.HTTP_BAD_REQUEST)

        # INIT #
        # schema = self.get_endpoint_custom_definition()
        # properties = self.read_properties(schema, v)

        if 'password' not in v:
            raise RestApiException(
                "Missing input: password", status_code=hcodes.HTTP_BAD_REQUEST
            )

        if 'email' not in v:
            raise RestApiException(
                "Missing input: email", status_code=hcodes.HTTP_BAD_REQUEST
            )

        if 'name' not in v:
            raise RestApiException(
                "Missing input: name", status_code=hcodes.HTTP_BAD_REQUEST
            )

        if 'surname' not in v:
            raise RestApiException(
                "Missing input: surname", status_code=hcodes.HTTP_BAD_REQUEST
            )

        user = self.auth.get_user_object(username=v['email'])
        if user is not None:
            raise RestApiException(
                "This user already exists: %s" % v['email'],
                status_code=hcodes.HTTP_BAD_REQUEST,
            )

        v['is_active'] = False
        user = self.auth.create_user(v, [self.auth.default_role])

        try:
            self.auth.custom_post_handle_user_input(user, v)
            send_activation_link(self.auth, user)
            notify_registration(user)
            msg = (
                "We are sending an email to your email address where "
                + "you will find the link to activate your account"
            )

        except BaseException as e:
            log.error("Errors during account registration: %s" % str(e))
            user.delete()
            raise RestApiException(str(e))
        else:
            custom_extra_registration(v)
            return msg

    def update_password(self, user, data):

        password = data.get('password')
        new_password = data.get('new_password')
        password_confirm = data.get('password_confirm')

        totp_authentication = (
            self.auth.SECOND_FACTOR_AUTHENTICATION is not None
            and self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP
        )
        if totp_authentication:
            totp_code = data.get('totp_code')
        else:
            totp_code = None

        security = HandleSecurity(self.auth)

        if new_password is None or password_confirm is None:
            msg = "New password is missing"
            raise RestApiException(msg, status_code=hcodes.HTTP_BAD_REQUEST)

        if totp_authentication:
            security.verify_totp(user, totp_code)
        else:
            token, _ = self.auth.make_login(user.email, password)
            security.verify_token(user.email, token)

        security.change_password(user, password, new_password, password_confirm)

        # NOTE already in change_password
        # but if removed new pwd is not saved
        return user.save()

    def update_profile(self, user, data):

        # log.pp(data)
        avoid_update = ['uuid', 'authmethod', 'is_active', 'roles']

        try:
            for key, value in data.items():
                if key.startswith('_') or key in avoid_update:
                    continue
                log.debug("Profile new value: %s=%s", key, value)
                setattr(user, key, value)
        except BaseException as e:
            log.error("Failed to update profile:\n%s: %s", e.__class__.__name__, e)
        else:
            log.info("Profile updated")

        return user.save()

    @decorate.catch_error()
    def put(self):
        """ Update profile for current user """

        user = self.auth.get_user()
        data = self.get_input()

        has_pw_update = True
        no_pw_data = {}
        for key in data.keys():
            if 'password' not in key:
                no_pw_data[key] = data[key]
                has_pw_update = False

        if has_pw_update:
            self.update_password(user, data)
        else:
            self.update_profile(user, no_pw_data)

        return self.empty_response()


class ProfileActivate(EndpointResource):
    @decorate.catch_error()
    def put(self, token_id):

        token_id = token_id.replace("+", ".")
        try:
            # Unpack and verify token. If ok, self.auth will be added with
            # auth._user auth._token and auth._jti
            self.auth.verify_token(
                token_id, raiseErrors=True, token_type=self.auth.ACTIVATE_ACCOUNT
            )

        # If token is expired
        except jwt.exceptions.ExpiredSignatureError as e:
            raise RestApiException(
                'Invalid activation token: this request is expired',
                status_code=hcodes.HTTP_BAD_REQUEST,
            )

        # if token is not yet active
        except jwt.exceptions.ImmatureSignatureError as e:
            raise RestApiException(
                'Invalid activation token', status_code=hcodes.HTTP_BAD_REQUEST
            )

        # if token does not exist (or other generic errors)
        except Exception as e:
            raise RestApiException(
                'Invalid activation token', status_code=hcodes.HTTP_BAD_REQUEST
            )

        # Recovering token object from jti
        token = self.auth.get_tokens(token_jti=self.auth._jti)
        if len(token) == 0:
            raise RestApiException(
                'Invalid activation token: this request is no longer valid',
                status_code=hcodes.HTTP_BAD_REQUEST,
            )

        # If user logged is already active, invalidate the token
        if self.auth._user.is_active is not None and self.auth._user.is_active:
            self.auth.invalidate_token(token_id)
            raise RestApiException(
                'Invalid activation token: this request is no longer valid',
                status_code=hcodes.HTTP_BAD_REQUEST,
            )

        # The activation token is valid, do something

        self.auth._user.is_active = True
        self.auth._user.save()

        # Bye bye token (reset activation are valid only once)
        self.auth.invalidate_token(token_id)

        return "Account activated"

    @decorate.catch_error()
    def post(self):

        v = self.get_input()
        if len(v) == 0:
            raise RestApiException('Empty input', status_code=hcodes.HTTP_BAD_REQUEST)

        if 'username' not in v:
            raise RestApiException(
                'Missing required input: username', status_code=hcodes.HTTP_BAD_REQUEST
            )

        user = self.auth.get_user_object(username=v['username'])

        # if user is None this endpoint does nothing and the response
        # remain the same (we are sending an email bla bla)
        # => security to avoid user guessing
        if user is not None:
            send_activation_link(self.auth, user)
        msg = (
            "We are sending an email to your email address where "
            + "you will find the link to activate your account"
        )
        return msg


def send_internal_password_reset(uri, title, reset_email):
    # Internal templating
    body = "Follow this link to reset password: %s" % uri
    html_body = get_html_template("reset_password.html", {"url": uri})
    if html_body is None:
        log.warning("Unable to find email template")
        html_body = body
        body = None
    subject = "%s Password Reset" % title

    # Internal email sending
    c = send_mail(html_body, subject, reset_email, plain_body=body)
    if not c:
        raise RestApiException("Error sending email, please retry")


class RecoverPassword(EndpointResource):

    baseuri = "/auth"
    depends_on = ["MAIN_LOGIN_ENABLE"]
    labels = ["authentication"]

    SPECS = {
        "mapping": {
            "ask_reset": "/reset",
            "do_reset": "/reset/<token_id>"
        }
    }
    POST = {
        "ask_reset": {
            "summary": "Request password reset via email",
            "description": "Request password reset via email",
            "custom": {
                "authentication": False,
                "publish": True
            },
            "responses": {
                "200": {
                    "description": "Reset email is valid"
                },
                "401": {
                    "description": "Invalid reset email"
                }
            }
        }
    }
    PUT = {
        "do_reset": {
            "summary": "Change password as conseguence of a reset request",
            "description": "Change password as conseguence of a reset request",
            "custom": {
                "authentication": False,
                "publish": True
            },
            "responses": {
                "200": {
                    "description": "Reset token is valid, password changed"
                },
                "401": {
                    "description": "Invalid reset token"
                }
            }
        }
    }

    @decorate.catch_error()
    def post(self):

        if not send_mail_is_active():
            raise RestApiException(
                'Server misconfiguration, unable to reset password. '
                + 'Please report this error to adminstrators',
                status_code=hcodes.HTTP_BAD_REQUEST,
            )

        reset_email = self.get_input(single_parameter='reset_email')

        if reset_email is None:
            raise RestApiException(
                'Invalid reset email', status_code=hcodes.HTTP_BAD_FORBIDDEN
            )

        reset_email = reset_email.lower()

        user = self.auth.get_user_object(username=reset_email)

        if user is None:
            raise RestApiException(
                'Sorry, %s ' % reset_email
                + 'is not recognized as a valid username or email address',
                status_code=hcodes.HTTP_BAD_FORBIDDEN,
            )

        if user.is_active is not None and not user.is_active:
            # Beware, frontend leverages on this exact message,
            # do not modified it without fix also on frontend side
            raise RestApiException(
                "Sorry, this account is not active",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED,
            )

        # title = mem.customizer._configurations \
        #     .get('project', {}) \
        #     .get('title', "Unkown title")

        title = glom(
            mem.customizer._configurations, "project.title", default='Unkown title'
        )

        reset_token, jti = self.auth.create_reset_token(user, self.auth.PWD_RESET)

        domain = os.environ.get("DOMAIN")
        if PRODUCTION:
            protocol = "https"
        else:
            protocol = "http"

        rt = reset_token.replace(".", "+")

        var = "RESET_PASSWORD_URI"
        uri = detector.get_global_var(key=var, default='/public/reset')
        complete_uri = "%s://%s%s/%s" % (protocol, domain, uri, rt)

        ##################
        # Send email with internal or external SMTP
        obj = meta.get_customizer_class('apis.profile', 'CustomReset')
        if obj is None:
            # normal activation + internal smtp
            send_internal_password_reset(complete_uri, title, reset_email)
        else:
            # external smtp
            obj.request_reset(user.name, user.email, complete_uri)

        ##################
        # Completing the reset task
        self.auth.save_token(user, reset_token, jti, token_type=self.auth.PWD_RESET)

        msg = (
            "We are sending an email to your email address where "
            + "you will find the link to enter a new password"
        )
        return msg

    @decorate.catch_error()
    def put(self, token_id):

        token_id = token_id.replace("+", ".")
        try:
            # Unpack and verify token. If ok, self.auth will be added with
            # auth._user auth._token and auth._jti
            self.auth.verify_token(
                token_id, raiseErrors=True, token_type=self.auth.PWD_RESET
            )

        # If token is expired
        except jwt.exceptions.ExpiredSignatureError as e:
            raise RestApiException(
                'Invalid reset token: this request is expired',
                status_code=hcodes.HTTP_BAD_REQUEST,
            )

        # if token is not yet active
        except jwt.exceptions.ImmatureSignatureError as e:
            raise RestApiException(
                'Invalid reset token', status_code=hcodes.HTTP_BAD_REQUEST
            )

        # if token does not exist (or other generic errors)
        except Exception as e:
            raise RestApiException(
                'Invalid reset token', status_code=hcodes.HTTP_BAD_REQUEST
            )

        # Recovering token object from jti
        token = self.auth.get_tokens(token_jti=self.auth._jti)
        if len(token) == 0:
            raise RestApiException(
                'Invalid reset token: this request is no longer valid',
                status_code=hcodes.HTTP_BAD_REQUEST,
            )

        token = token.pop(0)
        emitted = timestamp_from_string(token["emitted"])

        last_change = None
        # If user logged in after the token emission invalidate the token
        if self.auth._user.last_login is not None:
            last_change = self.auth._user.last_login
        # If user changed the pwd after the token emission invalidate the token
        elif self.auth._user.last_password_change is not None:
            last_change = self.auth._user.last_password_change

        if last_change is not None:

            try:
                expired = last_change >= emitted
            except TypeError:
                # pymongo has problems here:
                # http://api.mongodb.com/python/current/examples/
                #  datetimes.html#reading-time
                log.debug("Localizing last password change")
                expired = pytz.utc.localize(last_change) >= emitted

            if expired:
                self.auth.invalidate_token(token_id)
                raise RestApiException(
                    'Invalid reset token: this request is no longer valid',
                    status_code=hcodes.HTTP_BAD_REQUEST,
                )

        # The reset token is valid, do something
        data = self.get_input()
        new_password = data.get("new_password")
        password_confirm = data.get("password_confirm")

        # No password to be changed, just a token verification
        if new_password is None and password_confirm is None:
            return self.empty_response()

        # Something is missing
        if new_password is None or password_confirm is None:
            raise RestApiException(
                'Invalid password', status_code=hcodes.HTTP_BAD_REQUEST
            )

        if new_password != password_confirm:
            raise RestApiException(
                'New password does not match with confirmation',
                status_code=hcodes.HTTP_BAD_REQUEST,
            )

        security = HandleSecurity(self.auth)

        security.change_password(self.auth._user, None, new_password, password_confirm)
        # I really don't know why this save is required... since it is already
        # in change_password ... But if I remove it the new pwd is not saved...
        self.auth._user.save()

        # Bye bye token (reset tokens are valid only once)
        self.auth.invalidate_token(token_id)

        return "Password changed"
