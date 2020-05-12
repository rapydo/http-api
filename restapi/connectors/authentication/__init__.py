# -*- coding: utf-8 -*-

import re
from datetime import datetime, timedelta

import pytz

from restapi.services.detect import Detector
from restapi.connectors import Connector
from restapi.services.authentication import BaseAuthentication
from restapi.exceptions import RestApiException
from restapi.utilities.meta import Meta
from restapi.utilities.logs import log
from restapi.confs import get_project_configuration


if Detector.get_global_var("AUTH_SECOND_FACTOR_AUTHENTICATION", '') == 'TOTP':
    try:
        import pyotp
        import pyqrcode

        # import base64
        from io import BytesIO
    except ModuleNotFoundError:
        log.exit(
            "Missing libraries for TOTP 2FA authentication"
        )


class Authenticator(Connector):

    def get_connection_exception(self):
        return None

    def preconnect(self, **kwargs):
        return True

    def postconnect(self, obj, **kwargs):
        return True

    def connect(self, **kwargs):

        # What service will hold authentication?
        auth_service = self.variables.get('service')
        auth_module = Meta.get_authentication_module(auth_service)
        custom_auth = auth_module.Authentication()

        secret = str(custom_auth.import_secret(self.app.config['SECRET_KEY_FILE']))

        # Install self.app secret for oauth2
        # !?
        self.app.secret_key = secret + '_app'

        custom_auth.TOTP = 'TOTP'

        custom_auth.MIN_PASSWORD_LENGTH = int(
            self.variables.get("min_password_length", 8)
        )
        custom_auth.FORCE_FIRST_PASSWORD_CHANGE = (
            self.variables.get("force_first_password_change", False) == 'True'
        )
        custom_auth.VERIFY_PASSWORD_STRENGTH = (
            self.variables.get("verify_password_strength", False) == 'True'
        )
        custom_auth.MAX_PASSWORD_VALIDITY = int(
            self.variables.get("max_password_validity", 0)
        )
        custom_auth.DISABLE_UNUSED_CREDENTIALS_AFTER = int(
            self.variables.get("disable_unused_credentials_after", 0)
        )
        custom_auth.REGISTER_FAILED_LOGIN = (
            self.variables.get("register_failed_login", False) == 'True'
        )
        custom_auth.MAX_LOGIN_ATTEMPTS = int(
            self.variables.get("max_login_attempts", 0)
        )
        custom_auth.SECOND_FACTOR_AUTHENTICATION = self.variables.get(
            "second_factor_authentication", None
        )

        if custom_auth.SECOND_FACTOR_AUTHENTICATION == "None":
            custom_auth.SECOND_FACTOR_AUTHENTICATION = None

        return custom_auth

    def initialize(self, pinit, pdestroy, abackend=None):

        obj = self.get_instance()
        # NOTE: Inject the backend as the object 'db' inside the instance
        # IMPORTANT!!! this is the 'hat trick' that makes things possible
        obj.db = abackend

        if pinit:
            with self.app.app_context():
                obj.init_users_and_roles()
                log.info("Initialized authentication module")

        if pdestroy:
            log.error("Destroy not implemented for authentication service")

        return obj


class HandleSecurity:
    def __init__(self, auth):
        self.auth = auth

    @staticmethod
    def get_secret(user):

        return 'base32secret3232'
        # FIXME: use a real secret
        # hashes does not works... maybe too long??
        # import hashlib
        # secret = hashlib.sha224(user.email.encode('utf-8'))
        # return secret.hexdigest()
        # same problem with str(user.uuid)

        # neither email works (problems with the @ character?)

        # decoding errors...
        # return str(user.name)

        # return base64.b32encode(user.name.encode('utf-8'))

    def verify_token(self, username, token):
        if token is None:

            if self.auth.REGISTER_FAILED_LOGIN:
                self.auth.register_failed_login(username)
            msg = 'Invalid username or password'
            code = 401
            raise RestApiException(msg, status_code=code, is_warning=True)

    def verify_totp(self, user, totp_code):

        if totp_code is None:
            raise RestApiException('Invalid verification code', status_code=401)
        secret = HandleSecurity.get_secret(user)
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code):
            if self.auth.REGISTER_FAILED_LOGIN:
                self.auth.register_failed_login(user.email)
            raise RestApiException('Invalid verification code', status_code=401)

        return True

    @staticmethod
    def get_qrcode(user):

        secret = HandleSecurity.get_secret(user)
        totp = pyotp.TOTP(secret)

        project_name = get_project_configuration('project.title', "No project name")

        otpauth_url = totp.provisioning_uri(project_name)
        qr_url = pyqrcode.create(otpauth_url)
        qr_stream = BytesIO()
        qr_url.svg(qr_stream, scale=5)
        return qr_stream.getvalue()

    def verify_password_strength(self, pwd, old_pwd=None):

        if old_pwd is not None and pwd == old_pwd:
            return False, "The new password cannot match the previous password"

        if len(pwd) < self.auth.MIN_PASSWORD_LENGTH:
            return False, "Password is too short, use at least {} characters".format(
                self.auth.MIN_PASSWORD_LENGTH
            )

        if not re.search("[a-z]", pwd):
            return False, "Password is too weak, missing lower case letters"
        if not re.search("[A-Z]", pwd):
            return False, "Password is too weak, missing upper case letters"
        if not re.search("[0-9]", pwd):
            return False, "Password is too weak, missing numbers"

        special_characters = "[^a-zA-Z0-9]"
        if not re.search(special_characters, pwd):
            return False, "Password is too weak, missing special characters"

        return True, None

    def change_password(self, user, password, new_password, password_confirm):

        if new_password is None:
            raise RestApiException("Wrong new password", status_code=400)

        if password_confirm is None:
            raise RestApiException("Wrong password confirm", status_code=400)

        from restapi.confs import TESTING
        if TESTING:

            log.critical(new_password)
            log.critical(password_confirm)

        if new_password != password_confirm:
            msg = "Your password doesn't match the confirmation"
            raise RestApiException(msg, status_code=409)

        if self.auth.VERIFY_PASSWORD_STRENGTH:

            check, msg = self.verify_password_strength(
                new_password,
                old_pwd=password if password else user.password
            )

            if not check:
                raise RestApiException(msg, status_code=409)

        now = datetime.now(pytz.utc)
        user.password = BaseAuthentication.get_password_hash(new_password)
        user.last_password_change = now
        self.auth.save_user(user)

        tokens = self.auth.get_tokens(user=user)
        for token in tokens:
            try:
                self.auth.invalidate_token(token=token["token"])
            except BaseException as e:
                log.error(e)
                log.critical("Failed to invalidate token {}")

        return True

    def verify_blocked_username(self, username):

        if not self.auth.REGISTER_FAILED_LOGIN:
            # We do not register failed login
            return False
        if self.auth.MAX_LOGIN_ATTEMPTS <= 0:
            # We register failed login, but we do not set a max num of failures
            return False
        # FIXME: implement get_failed_login
        if self.auth.get_failed_login(username) < self.auth.MAX_LOGIN_ATTEMPTS:
            # We register and set a max, but user does not reached it yet
            return False
        # Dear user, you have exceeded the limit
        msg = (
            """
            Sorry, this account is temporarily blocked due to
            more than {} failed login attempts. Try again later""".format(
                self.auth.MAX_LOGIN_ATTEMPTS)
        )
        raise RestApiException(msg, status_code=401)

    def verify_blocked_user(self, user):

        if self.auth.DISABLE_UNUSED_CREDENTIALS_AFTER > 0:
            last_login = user.last_login
            now = datetime.now(pytz.utc)
            if last_login is not None:

                inactivity = timedelta(days=self.auth.DISABLE_UNUSED_CREDENTIALS_AFTER)
                valid_until = last_login + inactivity

                if valid_until < now:
                    msg = "Sorry, this account is blocked for inactivity"
                    raise RestApiException(msg, status_code=401)

    @staticmethod
    def verify_active_user(user):

        if not user.is_active:
            # Beware, frontend leverages on this exact message,
            # do not modified it without fix also on frontend side
            raise RestApiException(
                "Sorry, this account is not active",
                status_code=401,
            )
