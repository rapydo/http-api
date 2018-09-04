# -*- coding: utf-8 -*-

"""
Base endpoints: authorization, status, checks.
And a Farm: How to create endpoints into REST service.
"""

import pytz
import jwt
import os
from glom import glom

from datetime import datetime, timedelta
from flask import jsonify, current_app

from restapi import decorators as decorate
from restapi.exceptions import RestApiException
from restapi.rest.definition import EndpointResource
# from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from restapi.services.mail import send_mail, send_mail_is_active
from restapi.services.mail import get_html_template
from utilities import htmlcodes as hcodes
from utilities.time import timestamp_from_string
from utilities.globals import mem
from utilities.meta import Meta
from restapi.confs import PRODUCTION
from utilities.logs import get_logger

from restapi.flask_ext.flask_auth import HandleSecurity

log = get_logger(__name__)
meta = Meta()


class Status(EndpointResource):
    """ API online client testing """

    @decorate.catch_error()
    def get(self, service=None):

        return 'Server is alive!'


class Verify(EndpointResource):
    """ Service connection testing """

    @decorate.catch_error()
    def get(self, service):

        log.critical(detector.available_services)
        if not detector.check_availability(service):
            raise RestApiException(
                "Unknown service: %s" % service,
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED
            )

        service_instance = self.get_service_instance(
            service, global_instance=False)
        log.critical(service_instance)
        return "Service is reachable: %s" % service


class SwaggerSpecifications(EndpointResource):
    """
    Specifications output throught Swagger (open API) standards
    """

    def get(self):

        # NOTE: swagger dictionary is read only once, at server init time
        swagjson = mem.customizer._definitions

        # NOTE: changing dinamically options, based on where the client lies
        from restapi.confs import PRODUCTION
        from flask import request
        from utilities.helpers import get_api_url
        api_url = get_api_url(request, PRODUCTION)
        scheme, host = api_url.rstrip('/').split('://')
        swagjson['host'] = host
        swagjson['schemes'] = [scheme]

        # Jsonify, so we skip custom response building
        return jsonify(swagjson)


class Login(EndpointResource):
    """ Let a user login with the developer chosen method """

    def verify_information(
            self, user, security, totp_auth, totp_code, now=None):

        message_body = {}
        message_body['actions'] = []
        error_message = None

        if totp_auth and totp_code is None:
            message_body['actions'].append(
                self.auth.SECOND_FACTOR_AUTHENTICATION)
            error_message = "You do not provided a valid second factor"

        epoch = datetime.fromtimestamp(0, pytz.utc)
        last_pwd_change = user.last_password_change
        if last_pwd_change is None or last_pwd_change == 0:
            last_pwd_change = epoch

        if self.auth.FORCE_FIRST_PASSWORD_CHANGE and last_pwd_change == epoch:

            message_body['actions'].append('FIRST LOGIN')
            error_message = "Please change your temporary password"

            if totp_auth:

                qr_code = security.get_qrcode(user)

                message_body["qr_code"] = qr_code

        elif self.auth.MAX_PASSWORD_VALIDITY > 0:

            if last_pwd_change == epoch:
                expired = True
            else:
                valid_until = \
                    last_pwd_change + timedelta(
                        days=self.auth.MAX_PASSWORD_VALIDITY)

                if now is None:
                    now = datetime.now(pytz.utc)
                expired = (valid_until < now)

            if expired:

                message_body['actions'].append('PASSWORD EXPIRED')
                error_message = "Your password is expired, please change it"

        if error_message is None:
            return None

        return self.force_response(
            message_body, errors=error_message, code=hcodes.HTTP_BAD_FORBIDDEN)

    @decorate.catch_error()
    def post(self):

        # ########## INIT ##########
        jargs = self.get_input()
        username = jargs.get('username')
        if username is None:
            username = jargs.get('email')

        password = jargs.get('password')
        if password is None:
            password = jargs.get('pwd')

        # ##################################################
        # Now credentials are checked at every request
        if username is None or password is None:
            msg = "Missing username or password"
            raise RestApiException(
                msg, status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        username = username.lower()
        now = datetime.now(pytz.utc)

        new_password = jargs.get('new_password')
        password_confirm = jargs.get('password_confirm')

        totp_authentication = (
            self.auth.SECOND_FACTOR_AUTHENTICATION is not None and
            self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP
        )

        if totp_authentication:
            totp_code = jargs.get('totp_code')
        else:
            totp_code = None

        security = HandleSecurity(self.auth)
        # ##################################################
        # Authentication control
        security.verify_blocked_username(username)
        token, jti = self.auth.make_login(username, password)
        security.verify_token(username, token)
        user = self.auth.get_user()
        security.verify_blocked_user(user)
        security.verify_active_user(user)

        if totp_authentication and totp_code is not None:
            security.verify_totp(user, totp_code)

        # ##################################################
        # If requested, change the password
        if new_password is not None and password_confirm is not None:

            pwd_changed = security.change_password(
                user, password, new_password, password_confirm)

            if pwd_changed:
                password = new_password
                token, jti = self.auth.make_login(username, password)

        # ##################################################
        # Something is missing in the authentication, asking action to user
        ret = self.verify_information(
            user, security, totp_authentication, totp_code, now)
        if ret is not None:
            return ret

        # ##################################################
        # Everything is ok, let's save authentication information

        if user.first_login is None:
            user.first_login = now
        user.last_login = now
        # Should be saved inside save_token...
        # user.save()
        self.auth.save_token(self.auth._user, token, jti)

        # FIXME: split response as above in access_token and token_type?
        # # The right response should be the following
        # {
        #   "scope": "https://b2stage-test.cineca.it/api/.*",
        #   "access_token": "EEwJ6tF9x5WCIZDYzyZGaz6Khbw7raYRIBV_WxVvgmsG",
        #   "token_type": "Bearer",
        #   "user": "pippo",
        #   "expires_in": 28800
        # }
        # FIXME: also set headers in a standard way if it exists

        return {'token': token}


class Logout(EndpointResource):
    """ Let the logged user escape from here, invalidating current token """

    def get(self):
        self.auth.invalidate_token(token=self.auth.get_token())
        return self.empty_response()


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

    @decorate.catch_error()
    def post(self):

        if not send_mail_is_active():
            raise RestApiException(
                'Server misconfiguration, unable to reset password. ' +
                'Please report this error to adminstrators',
                status_code=hcodes.HTTP_BAD_REQUEST)

        reset_email = self.get_input(single_parameter='reset_email')

        if reset_email is None:
            raise RestApiException(
                'Invalid reset email',
                status_code=hcodes.HTTP_BAD_FORBIDDEN)

        reset_email = reset_email.lower()

        user = self.auth.get_user_object(username=reset_email)

        if user is None:
            raise RestApiException(
                'Sorry, %s ' % reset_email +
                'is not recognized as a valid username or email address',
                status_code=hcodes.HTTP_BAD_FORBIDDEN)

        if user.is_active is not None and not user.is_active:
            # Beware, frontend leverages on this exact message,
            # do not modified it without fix also on frontend side
            raise RestApiException(
                "Sorry, this account is not active",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        # title = mem.customizer._configurations \
        #     .get('project', {}) \
        #     .get('title', "Unkown title")

        title = glom(
            mem.customizer._configurations,
            "project.title",
            default='Unkown title')

        reset_token, jti = self.auth.create_reset_token(
            user, self.auth.PWD_RESET)

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
        self.auth.save_token(
            user, reset_token, jti, token_type=self.auth.PWD_RESET)

        msg = "We are sending an email to your email address where " + \
            "you will find the link to enter a new password"
        return msg

    @decorate.catch_error()
    def put(self, token_id):

        token_id = token_id.replace("+", ".")
        try:
            # Unpack and verify token. If ok, self.auth will be added with
            # auth._user auth._token and auth._jti
            self.auth.verify_token(
                token_id, raiseErrors=True, token_type=self.auth.PWD_RESET)

        # If token is expired
        except jwt.exceptions.ExpiredSignatureError as e:
            raise RestApiException(
                'Invalid reset token: this request is expired',
                status_code=hcodes.HTTP_BAD_REQUEST)

        # if token is not yet active
        except jwt.exceptions.ImmatureSignatureError as e:
            raise RestApiException(
                'Invalid reset token',
                status_code=hcodes.HTTP_BAD_REQUEST)

        # if token does not exist (or other generic errors)
        except Exception as e:
            raise RestApiException(
                'Invalid reset token',
                status_code=hcodes.HTTP_BAD_REQUEST)

        # Recovering token object from jti
        token = self.auth.get_tokens(token_jti=self.auth._jti)
        if len(token) == 0:
            raise RestApiException(
                'Invalid reset token: this request is no longer valid',
                status_code=hcodes.HTTP_BAD_REQUEST)

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
                    status_code=hcodes.HTTP_BAD_REQUEST)

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
                'Invalid password',
                status_code=hcodes.HTTP_BAD_REQUEST)

        if new_password != password_confirm:
            raise RestApiException(
                'New password does not match with confirmation',
                status_code=hcodes.HTTP_BAD_REQUEST)

        security = HandleSecurity(self.auth)

        security.change_password(
            self.auth._user, None, new_password, password_confirm)
        # I really don't know why this save is required... since it is already
        # in change_password ... But if I remove it the new pwd is not saved...
        self.auth._user.save()

        # Bye bye token (reset tokens are valid only once)
        self.auth.invalidate_token(token_id)

        return "Password changed"


class Tokens(EndpointResource):
    """ List all active tokens for a user """

    def get_user(self):

        iamadmin = self.auth.verify_admin()

        if iamadmin:
            username = self.get_input(single_parameter='username')
            if username is not None:
                username = username.lower()
                return self.auth.get_user_object(username=username)

        return self.get_current_user()

    def get(self, token_id=None):

        user = self.get_user()
        if user is None:
            return self.send_errors(
                message="Invalid: bad username", code=hcodes.HTTP_BAD_REQUEST)

        tokens = self.auth.get_tokens(user=user)
        if token_id is None:
            return tokens

        for token in tokens:
            if token["id"] == token_id:
                return token

        errorMessage = """Either this token was not emitted for your account
                          or it does not exist"""

        return self.send_errors(
            message=errorMessage, code=hcodes.HTTP_BAD_NOTFOUND)

    def delete(self, token_id=None):
        """
            For additional security, tokens are invalidated both
            by chanding the user UUID and by removing single tokens
        """

        user = self.get_user()
        if user is None:
            return self.send_errors(
                message="Invalid: bad username", code=hcodes.HTTP_BAD_REQUEST)

        if token_id is None:
            # NOTE: this is allowed only in removing tokens in unittests
            if not current_app.config['TESTING']:
                raise KeyError("TESTING IS FALSE! Specify a valid token")
            self.auth.invalidate_all_tokens(user=user)
            return self.empty_response()

        tokens = self.auth.get_tokens(user=user)

        for token in tokens:
            if token["id"] != token_id:
                continue
            if not self.auth.invalidate_token(token=token["token"], user=user):
                return self.send_errors(
                    message="Failed token invalidation: '%s'" % token,
                    code=hcodes.HTTP_BAD_REQUEST)
            log.debug("Token invalidated: %s", token_id)
            return self.empty_response()

        message = "Token not emitted for your account or does not exist"
        return self.send_errors(
            message=message, code=hcodes.HTTP_BAD_UNAUTHORIZED)


def send_activation_link(auth, user):

    title = glom(
        mem.customizer._configurations,
        "project.title",
        default='Unkown title')

    activation_token, jti = auth.create_reset_token(
        user, auth.ACTIVATE_ACCOUNT)

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
                e.__class__.__name__, e)
            raise

    auth.save_token(
        user, activation_token, jti,
        token_type=auth.ACTIVATE_ACCOUNT)


def notify_registration(user):
    var = "REGISTRATION_NOTIFICATIONS"
    if detector.get_bool_from_os(var):
        # Sending an email to the administrator
        title = glom(
            mem.customizer._configurations,
            "project.title",
            default='Unkown title')
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
                name=variables['name'], surname=variables['surname'])
        except BaseException as e:
            log.error(
                "Could not register your custom profile:\n%s: %s",
                e.__class__.__name__, e)


class Profile(EndpointResource):
    """ Current user informations """

    def get(self):

        current_user = self.get_current_user()
        data = {
            'uuid': current_user.uuid,
            'status': "Valid user",
            'email': current_user.email
        }

        roles = []
        for role in current_user.roles:
            roles.append(role.name)
        data["roles"] = roles

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
        """ Create new user """

        if not send_mail_is_active():
            raise RestApiException(
                'Server misconfiguration, unable to reset password. ' +
                'Please report this error to adminstrators',
                status_code=hcodes.HTTP_BAD_REQUEST)

        v = self.get_input()
        if len(v) == 0:
            raise RestApiException(
                'Empty input',
                status_code=hcodes.HTTP_BAD_REQUEST)

        # INIT #
        # schema = self.get_endpoint_custom_definition()
        # properties = self.read_properties(schema, v)

        if 'password' not in v:
            raise RestApiException(
                "Missing input: password",
                status_code=hcodes.HTTP_BAD_REQUEST)

        if 'email' not in v:
            raise RestApiException(
                "Missing input: email",
                status_code=hcodes.HTTP_BAD_REQUEST)

        if 'name' not in v:
            raise RestApiException(
                "Missing input: name",
                status_code=hcodes.HTTP_BAD_REQUEST)

        if 'surname' not in v:
            raise RestApiException(
                "Missing input: surname",
                status_code=hcodes.HTTP_BAD_REQUEST)

        user = self.auth.get_user_object(username=v['email'])
        if user is not None:
            raise RestApiException(
                "This user already exists: %s" % v['email'],
                status_code=hcodes.HTTP_BAD_REQUEST)

        v['is_active'] = False
        user = self.auth.create_user(v, [self.auth.default_role])

        try:
            self.auth.custom_post_handle_user_input(user, v)
            send_activation_link(self.auth, user)
            notify_registration(user)
            msg = "We are sending an email to your email address where " + \
                "you will find the link to activate your account"

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
            self.auth.SECOND_FACTOR_AUTHENTICATION is not None and
            self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP
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

        security.change_password(
            user, password, new_password, password_confirm)

        # NOTE already in change_password
        # but if removed new pwd is not saved
        return user.save()

    def update_profile(self, user, data):

        # log.pp(data)
        avoid_update = [
            'uuid', 'authmethod', 'is_active', 'roles'
        ]

        try:
            for key, value in data.items():
                if key.startswith('_') or key in avoid_update:
                    continue
                log.debug("Profile new value: %s=%s", key, value)
                setattr(user, key, value)
        except BaseException as e:
            log.error(
                "Failed to update profile:\n%s: %s",
                e.__class__.__name__, e
            )
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
                token_id, raiseErrors=True,
                token_type=self.auth.ACTIVATE_ACCOUNT)

        # If token is expired
        except jwt.exceptions.ExpiredSignatureError as e:
            raise RestApiException(
                'Invalid activation token: this request is expired',
                status_code=hcodes.HTTP_BAD_REQUEST)

        # if token is not yet active
        except jwt.exceptions.ImmatureSignatureError as e:
            raise RestApiException(
                'Invalid activation token',
                status_code=hcodes.HTTP_BAD_REQUEST)

        # if token does not exist (or other generic errors)
        except Exception as e:
            raise RestApiException(
                'Invalid activation token',
                status_code=hcodes.HTTP_BAD_REQUEST)

        # Recovering token object from jti
        token = self.auth.get_tokens(token_jti=self.auth._jti)
        if len(token) == 0:
            raise RestApiException(
                'Invalid activation token: this request is no longer valid',
                status_code=hcodes.HTTP_BAD_REQUEST)

        # If user logged is already active, invalidate the token
        if self.auth._user.is_active is not None and \
                self.auth._user.is_active:
            self.auth.invalidate_token(token_id)
            raise RestApiException(
                'Invalid activation token: this request is no longer valid',
                status_code=hcodes.HTTP_BAD_REQUEST)

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
            raise RestApiException(
                'Empty input',
                status_code=hcodes.HTTP_BAD_REQUEST)

        if 'username' not in v:
            raise RestApiException(
                'Missing required input: username',
                status_code=hcodes.HTTP_BAD_REQUEST)

        user = self.auth.get_user_object(username=v['username'])

        # if user is None this endpoint does nothing and the response
        # remain the same (we are sending an email bla bla)
        # => security to avoid user guessing
        if user is not None:
            send_activation_link(self.auth, user)
        msg = "We are sending an email to your email address where " + \
            "you will find the link to activate your account"
        return msg


###########################
# NOTE: roles are configured inside swagger definitions
class Internal(EndpointResource):
    """ Token and Role authentication test """

    def get(self):
        return "I am internal"


class Admin(EndpointResource):
    """ Token and Role authentication test """

    def get(self):
        return "I am admin!"


###########################
# In case you have celery queue,
# you get a queue endpoint for free
if detector.check_availability('celery'):

    class Queue(EndpointResource):

        def get(self, task_id=None):

            data = []
            # Inspect all worker nodes
            celery = self.get_service_instance('celery')

            if task_id is not None:
                task_result = celery.AsyncResult(task_id)
                res = task_result.result
                if not isinstance(res, dict):
                    res = str(res)
                return {
                    'status': task_result.status,
                    # 'info': task_result.info,
                    'output': res,
                }

            #############################
            # FAST WAY
            stats = celery.control.inspect().stats()
            workers = list(stats.keys())

            active_tasks = {}
            revoked_tasks = {}
            scheduled_tasks = {}
            reserved_tasks = {}

            for worker in workers:
                i = celery.control.inspect([worker])
                log.debug('checked worker: %s', worker)
                for key, value in i.active().items():
                    active_tasks[key] = value
                for key, value in i.revoked().items():
                    revoked_tasks[key] = value
                for key, value in i.reserved().items():
                    reserved_tasks[key] = value
                for key, value in i.scheduled().items():
                    scheduled_tasks[key] = value

            #############################
            # workers = celery.control.inspect()
            # SLOW WAY
            # active_tasks = workers.active()
            # revoked_tasks = workers.revoked()
            # reserved_tasks = workers.reserved()
            # scheduled_tasks = workers.scheduled()
            # SLOW WAY
            # if active_tasks is None:
            #     active_tasks = []
            # if revoked_tasks is None:
            #     revoked_tasks = []
            # if scheduled_tasks is None:
            #     scheduled_tasks = []
            # if reserved_tasks is None:
            #     reserved_tasks = []

            log.verbose('listing items')
            for worker, tasks in active_tasks.items():
                for task in tasks:
                    if task_id is not None and task["id"] != task_id:
                        continue

                    row = {}
                    row['status'] = 'ACTIVE'
                    row['worker'] = worker
                    row['ETA'] = task["time_start"]
                    row['task_id'] = task["id"]
                    row['task'] = task["name"]
                    row['args'] = task["args"]

                    if task_id is not None:
                        task_result = celery.AsyncResult(task_id)
                        row['task_status'] = task_result.status
                        row['info'] = task_result.info
                    data.append(row)

            for worker, tasks in revoked_tasks.items():
                for task in tasks:
                    if task_id is not None and task != task_id:
                        continue
                    row = {}
                    row['status'] = 'REVOKED'
                    row['task_id'] = task
                    data.append(row)

            for worker, tasks in scheduled_tasks.items():
                for task in tasks:
                    if task_id is not None and \
                       task["request"]["id"] != task_id:
                        continue

                    row = {}
                    row['status'] = 'SCHEDULED'
                    row['worker'] = worker
                    row['ETA'] = task["eta"]
                    row['task_id'] = task["request"]["id"]
                    row['priority'] = task["priority"]
                    row['task'] = task["request"]["name"]
                    row['args'] = task["request"]["args"]
                    data.append(row)

            for worker, tasks in reserved_tasks.items():
                for task in tasks:
                    if task_id is not None and \
                       task["id"] != task_id:
                        continue

                    data.append({
                        'status': 'SCHEDULED',
                        'worker': worker,
                        'ETA': task['time_start'],
                        'task_id': task["id"],
                        'priority': task['delivery_info']["priority"],
                        'task': task["name"],
                        'args': task["args"],
                    })

            # from celery.task.control import inspect
            # tasks = inspect()
            log.verbose('listing completed')

            return self.force_response(data)

        def put(self, task_id):
            celery = self.get_service_instance('celery')
            celery.control.revoke(task_id)
            return self.empty_response()

        def delete(self, task_id):
            celery = self.get_service_instance('celery')
            celery.control.revoke(task_id, terminate=True)
            return self.empty_response()
