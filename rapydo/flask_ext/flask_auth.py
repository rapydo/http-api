# -*- coding: utf-8 -*-

import re
import pytz
from datetime import datetime, timedelta
from rapydo.services.detect import Detector

# from rapydo.confs import PRODUCTION
from rapydo.flask_ext import BaseExtension, get_logger
from rapydo.services.authentication import BaseAuthentication
from rapydo.utils import htmlcodes as hcodes
from rapydo.exceptions import RestApiException
from rapydo.utils.globals import mem

log = get_logger(__name__)

if Detector.get_global_var("AUTH_SECOND_FACTOR_AUTHENTICATION", '') == 'TOTP':
    try:
        import pyotp
        import pyqrcode
        # import base64
        from io import BytesIO
    # TOFIX: cannot use the proper exception (available in python 3.6+)
    # because we are stuck on python 3.5 con IMC
    # except ModuleNotFoundError:
    except BaseException:
        log.critical_exit("You enabled TOTP 2FA authentication" +
                          ", but related libraries are not installed")


class Authenticator(BaseExtension):
    """
    The generic authentication Flask extension
    """

    def custom_connection(self, **kwargs):

        # # What service will hold authentication?
        auth_service = self.variables.get('service')
        auth_module = self.meta.get_authentication_module(auth_service)
        custom_auth = auth_module.Authentication()

        # If oauth services are available, set them before every request
        from rapydo.services.oauth2clients import ExternalLogins as oauth2

        # TOFIX: from MATTIA: I removed this IF and always create oauth2()
        # because before of this none create an instance of ExternalLogins to
        # populate the dictionary of oauth2 services. To fix by putting this
        # inizialization somewhere
        # if oauth2._check_if_services_exist():
        #     ext_auth = oauth2(self.app.config['TESTING'])
        #     custom_auth.set_oauth2_services(ext_auth._available_services)

        # TOFIX: FROM MATTIA: the testing parameter is still required?
        ext_auth = oauth2(self.app.config['TESTING'])
        custom_auth.set_oauth2_services(ext_auth._available_services)

        # TOFIX: why tests should use a custom secret?
        # In this way we cannot test the import_secret
        if self.app.config['TESTING']:
            secret = 'IaMvERYsUPERsECRET'
        else:
            secret = str(
                custom_auth.import_secret(self.app.config['SECRET_KEY_FILE'])
            )

        # Install self.app secret for oauth2
        self.app.secret_key = secret + '_app'

        # Enabling also OAUTH library
        from rapydo.protocols.oauth import oauth
        oauth.init_app(self.app)

        custom_auth.TOTP = 'TOTP'

        custom_auth.REGISTER_FAILED_LOGIN = \
            self.variables.get("register_failed_login", False) == 'True'
        custom_auth.FORCE_FIRST_PASSWORD_CHANGE = \
            self.variables.get("force_first_password_change", False) == 'True'
        custom_auth.VERIFY_PASSWORD_STRENGTH = \
            self.variables.get("verify_password_strength", False) == 'True'
        custom_auth.MAX_PASSWORD_VALIDITY = \
            int(self.variables.get("max_password_validity", 0))
        custom_auth.DISABLE_UNUSED_CREDENTIALS_AFTER = \
            int(self.variables.get("disable_unused_credentials_after", 0))
        custom_auth.MAX_LOGIN_ATTEMPTS = \
            int(self.variables.get("max_login_attempts", 0))
        custom_auth.SECOND_FACTOR_AUTHENTICATION = \
            self.variables.get("second_factor_authentication", None)

        if custom_auth.SECOND_FACTOR_AUTHENTICATION == "None":
            custom_auth.SECOND_FACTOR_AUTHENTICATION = None

        return custom_auth

    def custom_init(self, pinit=False, pdestroy=False, abackend=None):

        # Get the instance from the parent
        obj = super().custom_init()
        # Inject the backend as the object 'db' inside the instance
        # IMPORTANT: this is the 'hat trick' that makes things possible
        obj.db = abackend

        if pinit:
            with self.app.app_context():
                obj.init_users_and_roles()
                log.info("Initialized authentication module")
        # elif PRODUCTION:
        #     """
        #     # TODO: check if this piece of code works
        #     and
        #     # TOFIX: what if launched in production for the first time?
        #     """
        #     if obj.check_if_user_defaults():
        #         raise ValueError("Production with default admin user")


class HandleSecurity(object):

    def __init__(self, auth):
        self.auth = auth

    def get_secret(self, user):

        return 'base32secret3232'
        # TOFIX: use a real secret
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
            code = hcodes.HTTP_BAD_UNAUTHORIZED
            raise RestApiException(msg, status_code=code)

    def verify_totp(self, user, totp_code):

        valid = True

        if totp_code is None:
            valid = False
        else:
            secret = self.get_secret(user)
            totp = pyotp.TOTP(secret)
            if not totp.verify(totp_code):
                if self.auth.REGISTER_FAILED_LOGIN:
                    self.auth.register_failed_login(user.email)
                valid = False

        if not valid:
            msg = 'Invalid verification code'
            code = hcodes.HTTP_BAD_UNAUTHORIZED
            raise RestApiException(msg, status_code=code)

        return True

    def get_qrcode(self, user):

        secret = self.get_secret(user)
        totp = pyotp.TOTP(secret)

        global_conf = mem.customizer._configurations
        project_conf = global_conf.get('project', {})
        project_name = project_conf.get('title', "No project name")

        otpauth_url = totp.provisioning_uri(project_name)
        qr_url = pyqrcode.create(otpauth_url)
        qr_stream = BytesIO()
        qr_url.svg(qr_stream, scale=5)
        return qr_stream.getvalue()

    # TOFIX: check password strength, if required
    def verify_password_strength(self, pwd, old_pwd):

        if pwd == old_pwd:
            return False, "Password cannot match the previous password"
        if len(pwd) < 8:
            return False, "Password is too short, use at least 8 characters"

        if not re.search("[a-z]", pwd):
            return False, "Password is too simple, missing lower case letters"
        if not re.search("[A-Z]", pwd):
            return False, "Password is too simple, missing upper case letters"
        if not re.search("[0-9]", pwd):
            return False, "Password is too simple, missing numbers"

        # special_characters = "['\s!#$%&\"(),*+,-./:;<=>?@[\\]^_`{|}~']"
        special_characters = "[^a-zA-Z0-9]"
        if not re.search(special_characters, pwd):
            return False, "Password is too simple, missing special characters"

        return True, None

    def change_password(self, user, password, new_password, password_confirm):

        if new_password != password_confirm:
            msg = "Your password doesn't match the confirmation"
            raise RestApiException(msg, status_code=hcodes.HTTP_BAD_CONFLICT)

        if self.auth.VERIFY_PASSWORD_STRENGTH:
            check, msg = self.verify_password_strength(
                new_password, password)

            if not check:
                raise RestApiException(
                    msg, status_code=hcodes.HTTP_BAD_CONFLICT)

        if new_password is not None and password_confirm is not None:
            now = datetime.now(pytz.utc)
            user.password = BaseAuthentication.hash_password(new_password)
            user.last_password_change = now
            user.save()

            tokens = self.auth.get_tokens(user=user)
            for token in tokens:
                self.auth.invalidate_token(token=token["token"])
            # changes the user uuid invalidating all tokens
            self.auth.invalidate_all_tokens()

        return True

    def verify_blocked_username(self, username):

        if not self.auth.REGISTER_FAILED_LOGIN:
            # We do not register failed login
            pass
        elif self.auth.MAX_LOGIN_ATTEMPTS <= 0:
            # We register failed login, but we do not put a max num of failures
            pass
            # TOFIX: implement get_failed_login
        elif self.auth.get_failed_login(username) < \
                self.auth.MAX_LOGIN_ATTEMPTS:
            # We register and put a max, but user does not reached it yet
            pass
        else:
            # Dear user, you have exceeded the limit
            msg = """
                Sorry, this account is temporarily blocked due to
                more than %d failed login attempts. Try again later"""\
                % self.auth.MAX_LOGIN_ATTEMPTS
            code = hcodes.HTTP_BAD_UNAUTHORIZED
            raise RestApiException(msg, status_code=code)

    def verify_blocked_user(self, user):

        if self.auth.DISABLE_UNUSED_CREDENTIALS_AFTER > 0:
            last_login = user.last_login
            now = datetime.now(pytz.utc)
            code = hcodes.HTTP_BAD_UNAUTHORIZED
            if last_login is not None:

                inactivity = timedelta(
                    days=self.auth.DISABLE_UNUSED_CREDENTIALS_AFTER)
                valid_until = last_login + inactivity

                if valid_until < now:
                    msg = "Sorry, this account is blocked for inactivity"
                    raise RestApiException(msg, status_code=code)
