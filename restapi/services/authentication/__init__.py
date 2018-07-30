# -*- coding: utf-8 -*-

"""
SECURITY ENDPOINTS CHECK
Add auth checks called /checklogged and /testadmin
"""

import abc
import jwt
import hmac
import hashlib
import base64
import pytz
import socket

from utilities import CUSTOM_PACKAGE
from utilities.uuid import getUUID
from datetime import datetime, timedelta
from flask import current_app, request
from restapi.services.detect import Detector
from restapi.confs import PRODUCTION
from restapi.attributes import ALL_ROLES, ANY_ROLE
from utilities.meta import Meta
from utilities.globals import mem
from utilities import htmlcodes as hcodes
from utilities.logs import get_logger

log = get_logger(__name__)


class BaseAuthentication(metaclass=abc.ABCMeta):

    """
    An almost abstract class with methods
    to be implemented with a new service
    that aims to store credentials of users and roles.
    """

    ##########################
    # This string will be replaced with a proper secret file
    JWT_SECRET = 'top secret!'
    JWT_ALGO = 'HS256'
    # FIXME: already defined in auth.py HTTPAUTH_DEFAULT_SCHEME
    token_type = 'Bearer'

    FULL_TOKEN = "f"
    PWD_RESET = "r"
    ACTIVATE_ACCOUNT = "a"
    ##########################
    _oauth2 = {}

    longTTL = 2592000     # 1 month in seconds
    shortTTL = 604800     # 1 week in seconds

    def __init__(self):
        # TODO: myinit is a class method for unittest could it be fixed?
        self.myinit()
        # Create variables to be fulfilled by the authentication decorator
        self._token = None
        self._jti = None
        self._user = None
        self.defaultTTL = float(Detector.get_global_var(
            'TOKEN_DEFAULT_TTL', self.shortTTL))

    @classmethod
    def myinit(cls):
        """
        Note: converted as a classmethod to use inside unittests
        # TODO: check if still necessary
        """

        credentials = mem.customizer._configurations \
            .get('variables', {}) \
            .get('backend', {}) \
            .get('credentials', {})

        cls.default_user = credentials.get('username', None)
        cls.default_password = credentials.get('password', None)
        if cls.default_user is None or cls.default_password is None:
            raise AttributeError("Default credentials unavailable!")

        roles = credentials.get('roles', {})
        cls.default_role = roles.get('default')
        cls.role_admin = roles.get('admin')
        cls.default_roles = [
            roles.get('user'),
            roles.get('internal'),
            cls.role_admin
        ]
        if cls.default_role is None or None in cls.default_roles:
            raise AttributeError("Default roles are not available!")

    # @abc.abstractmethod
    # def __init__(self, services=None):
    #     """
    #     Make sure you can create an instance/connection,
    #     or reuse one service from `server.py` operations.
    #     """
    #     return

    def make_login(self, username, password):
        """ The method which will check if credentials are good to go """

        try:
            user = self.get_user_object(username=username)
        except BaseException as e:
            log.error("Unable to connect to auth backend\n[%s] %s", type(e), e)
            # log.critical("Please reinitialize backend tables")
            from restapi.exceptions import RestApiException
            raise RestApiException(
                "Server authentication misconfiguration",
                status_code=hcodes.HTTP_SERVER_ERROR
            )

        if user is None:
            return None, None

        try:
            # Check if Oauth2 is enabled
            if user.authmethod != 'credentials':
                return None, None
        except BaseException:
            # Missing authmethod as requested for authentication
            log.critical("Current authentication db models are broken!")
            return None, None

        if self.check_passwords(user.password, password):
            return self.create_token(self.fill_payload(user))

        return None, None

    # ########################
    # # Configure Secret Key #
    # ########################
    def import_secret(self, abs_filename):
        """
        Configure the JWT_SECRET from a file

        If the file does not exist, print instructions
        to create it from a shell with a random key
        and continues with default key
        """

        try:
            self.JWT_SECRET = open(abs_filename, 'rb').read()
        except IOError:
            log.warning(
                "Jwt secret file %s not found, using default", abs_filename)
            log.info("To create your own secret file:\n" +
                     "head -c 24 /dev/urandom > %s" % abs_filename)

        return self.JWT_SECRET

    def set_oauth2_services(self, services):
        self._oauth2 = services

    # #####################
    # # Password handling #
    # #####################
    @staticmethod
    def encode_string(string):
        """ Encodes a string to bytes, if it isn't already. """
        if isinstance(string, str):
            string = string.encode('utf-8')
        return string

    @staticmethod
    def hash_password(password):
        """ Original source:
        # https://github.com/mattupstate/flask-security
        #    /blob/develop/flask_security/utils.py#L110
        """

        salt = "Unknown"

        h = hmac.new(
            BaseAuthentication.encode_string(salt),
            BaseAuthentication.encode_string(password),
            hashlib.sha512)
        return base64.b64encode(h.digest()).decode('ascii')

    @staticmethod
    def check_passwords(hashed_password, password):
        proposed_password = BaseAuthentication.hash_password(password)
        return hashed_password == proposed_password

    # ########################
    # # Retrieve information #
    # ########################

    def get_user(self):
        """
            Current user, obtained by the authentication decorator
            inside the same Request (which is the same object instance)
        """
        return self._user

    def get_token(self):
        """
            Current token obtained by the authentication decorator
        """
        return self._token

    @abc.abstractmethod
    def get_user_object(self, username=None, payload=None):
        """
        How to retrieve the user from the current service,
        based on the unique username given, or from the content of the token
        """
        return

    @abc.abstractmethod
    def get_tokens(self, user=None, token_jti=None):
        """
            Return the list of all active tokens
        """
        return

    @staticmethod
    def get_host_info():

        ###############
        # Note: timeout do not work on dns lookup...
        # also read:
        # http://depier.re/attempts_to_speed_up_gethostbyaddr/

        # # if getting slow when network is unreachable
        # timer = 1
        # if hasattr(socket, 'setdefaulttimeout'):
        #     socket.setdefaulttimeout(timer)
        # # socket.socket.settimeout(timer)

        ###############
        hostname = ""

        if 'X-Forwarded-For' in request.headers:
            forwarded_ips = request.headers['X-Forwarded-For']
            ip = current_app.wsgi_app.get_remote_addr([forwarded_ips])
        else:
            ip = request.remote_addr
            if PRODUCTION:
                log.warning(
                    "Server in production X-Forwarded-For header is missing")

        if current_app.config['TESTING'] and ip is None:
            pass
        elif PRODUCTION:
            try:
                # note: this will return the ip if hostname is not available
                # hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
                hostname, _, _ = socket.gethostbyaddr(ip)
            except Exception as e:
                log.warning("Error resolving '%s': '%s'", ip, e)
        return ip, hostname

    # ###################
    # # Tokens handling #
    # ###################
    def create_token(self, payload):
        """ Generate a byte token with JWT library to encrypt the payload """
        self._user = self.get_user_object(payload=payload)
        encode = jwt.encode(
            payload, self.JWT_SECRET, algorithm=self.JWT_ALGO).decode('ascii')

        return encode, payload['jti']

    def create_temporary_token(self, user, duration=300, token_type=None):
        expiration = timedelta(seconds=duration)
        payload = self.fill_payload(
            user, expiration=expiration, token_type=token_type)
        return self.create_token(payload)

    def create_reset_token(self, user, type, duration=86400):
        # invalidate previous reset tokens
        tokens = self.get_tokens(user=user)
        for t in tokens:
            token_type = t.get("token_type")
            if token_type is None:
                continue
            if token_type != type:
                continue

            tok = t.get("token")
            if self.invalidate_token(tok):
                log.info("Previous token invalidated: %s", tok)

        # Generate a new reset token
        new_token, jti = self.create_temporary_token(
            user, duration=duration, token_type=type)

        return new_token, jti

    @abc.abstractmethod
    def verify_token_custom(self, jti, user, payload):
        """
            This method MUST be implemented by specific Authentication Methods
            to add more specific validation contraints
        """
        return

    @abc.abstractmethod
    def refresh_token(self, jti):
        """
            Verify shortTTL to refresh token if not expired
            Invalidate token otherwise
        """
        return

    def unpack_token(self, token, raiseErrors=False):

        payload = None
        try:
            payload = jwt.decode(
                token, self.JWT_SECRET, algorithms=[self.JWT_ALGO])
        # now > exp
        except jwt.exceptions.ExpiredSignatureError as e:
            # should this token be invalidated into the DB?
            if raiseErrors:
                raise(e)
            else:
                log.warning("Unable to decode JWT token. %s", e)
        # now < nbf
        except jwt.exceptions.ImmatureSignatureError as e:
            if raiseErrors:
                raise(e)
            else:
                log.warning("Unable to decode JWT token. %s", e)
        except Exception as e:
            if raiseErrors:
                raise(e)
            else:
                log.warning("Unable to decode JWT token. %s", e)

        return payload

    def verify_token(self, token, raiseErrors=False, token_type=None):

        # Force token cleaning
        payload = {}
        self._user = None

        if token is None:
            return False

        # Decode the current token
        tmp_payload = self.unpack_token(token, raiseErrors=raiseErrors)
        if tmp_payload is None:
            return False
        else:
            payload = tmp_payload

        payload_type = payload.get("t", self.FULL_TOKEN)

        if token_type is None:
            token_type = self.FULL_TOKEN

        if token_type != payload_type:
            log.error(
                "Invalid token type %s, required: %s",
                payload_type, token_type)
            return False

        # Get the user from payload
        self._user = self.get_user_object(payload=payload)
        if self._user is None:
            return False

        if not self.verify_token_custom(
           user=self._user,
           jti=payload['jti'], payload=payload):
            return False
        # e.g. for graph: verify the (token <- user) link

        if not self.refresh_token(payload['jti']):
            return False

        logfunc = log.verbose
        if current_app.config['TESTING']:
            logfunc = log.very_verbose
        logfunc("User authorized")

        self._token = token
        self._jti = payload['jti']
        return True

    def save_token(self, user, token, jti, token_type=None):
        log.debug("Token is not saved in base authentication")

    @abc.abstractmethod
    def invalidate_all_tokens(self, user=None):
        """
            With this method all token emitted for this user must be
            invalidated (no longer valid starting from now)
        """
        return

    @abc.abstractmethod
    def invalidate_token(self, token, user=None):
        """
            With this method the specified token must be invalidated
            as expected after a user logout
        """
        return

# FIXME payload should be some basic part + custom payload from the developer
    def fill_custom_payload(self, userobj, payload):
        """
            This method can be implemented by specific Authentication Methods
            to add more specific payload content
        """
        return payload

    def fill_payload(self, userobj, expiration=None, token_type=None):
        """ Informations to store inside the JWT token,
        starting from the user obtained from the current service

        Claim attributes listed here:
        http://blog.apcelent.com/json-web-token-tutorial-example-python.html

        TTL is measured in seconds
        """

        if expiration is None:
            expiration = timedelta(seconds=self.longTTL)

        payload = {
            'user_id': userobj.uuid,
            'jti': getUUID()
        }

        short_jwt = \
            Detector.get_global_var('AUTH_FULL_JWT_PAYLOAD', '') \
            .lower() == 'false'

        if token_type is not None:
            if token_type == self.PWD_RESET or \
               token_type == self.ACTIVATE_ACCOUNT:
                short_jwt = True
                payload["t"] = token_type

        if not short_jwt:
            now = datetime.now(pytz.utc)
            nbf = now   # you can add a timedelta
            exp = now + expiration
            payload['iat'] = now
            payload['nbf'] = nbf
            payload['exp'] = exp

        return self.fill_custom_payload(userobj, payload)

    # ##################
    # # Roles handling #
    # ##################
    def verify_roles(self, roles, required_roles=None, warnings=True):

        if required_roles is None:
            required_roles = ALL_ROLES

        current_roles = self.get_roles_from_user()

        if required_roles == ALL_ROLES:
            for role in roles:
                if role not in current_roles:
                    if warnings:
                        log.warning("Auth role '%s' missing for request", role)
                    return False
            return True

        if required_roles == ANY_ROLE:
            for role in roles:
                if role in current_roles:
                    return True
            return False

        log.critical(
            "Unknown role authorization requirement: %s", required_roles)
        return False

    def verify_admin(self):
        """ Check if current user has administration role """
        return self.verify_roles([self.role_admin], warnings=False)

    def verify_local_admin(self):
        return self.verify_roles(["local_admin"], warnings=False)

    @abc.abstractmethod
    def get_roles_from_user(self, userobj=None):
        """
        How to retrieve the role of a user from the current service,
        based on a user object.
        If not provided, uses the current user obj stored in self._user.
        """
        return

    # #################
    # # Database init #
    # #################
    def avoid_defaults(self):
        """
        Check in production if using the default user...
        """

        user = self.get_user_object(username=self.default_user)
        if user is not None and user.email == self.default_user:
            if user.password == self.hash_password(self.default_password):
                return True
        return False

    @abc.abstractmethod
    def init_users_and_roles(self):
        """
        Create roles and a user if no one exists.
        A possible algorithm:

        if not exist_one_role():
            for role in self.DEFAULT_ROLES:
                create_role(role)
        if not exist_one_user():
            create_user(
                email=self.DEFAULT_USER,
                name="Whatever", surname="YouLike",
                password=self.DEFAULT_PASSWORD,
                roles=DEFAULT_ROLES)
        """
        return

    def custom_user_properties(self, userdata):
        meta = Meta()
        module_path = "%s.%s.%s" % \
            (CUSTOM_PACKAGE, 'initialization', 'initialization')
        module = meta.get_module_from_string(
            module_path,
            debug_on_fail=False,
        )

        Customizer = meta.get_class_from_string(
            'Customizer', module, skip_error=True
        )
        if Customizer is None:
            log.debug("No user properties customizer available")
        else:
            try:
                userdata = Customizer().custom_user_properties(userdata)
            except BaseException as e:
                log.error("Unable to customize user properties: %s", e)

        if "email" in userdata:
            userdata["email"] = userdata["email"].lower()

        return userdata

    def custom_post_handle_user_input(self, user_node, input_data):
        meta = Meta()
        module_path = "%s.%s.%s" % \
            (CUSTOM_PACKAGE, 'initialization', 'initialization')
        module = meta.get_module_from_string(
            module_path,
            debug_on_fail=False,
        )

        Customizer = meta.get_class_from_string(
            'Customizer', module, skip_error=True
        )
        if Customizer is None:
            log.debug("No user properties customizer available")
        else:
            try:
                Customizer().custom_post_handle_user_input(
                    self, user_node, input_data
                )
            except BaseException as e:
                log.error("Unable to customize user properties: %s", e)

    # ################
    # # Create Users #
    # ################
    # @abc.abstractmethod
    def create_user(self, userdata, roles):
        """
        A method to create a new user following some standards.
        - The user should be at least associated to the default (basic) role
        - More to come
        """
        return

    @abc.abstractmethod
    def store_oauth2_user(self, current_user, token):
        """
        Allow external accounts (oauth2 credentials)
        to be connected to internal local user.

        (requires an ExternalAccounts model defined for current service)
        """
        return ('internal_user', 'external_user')

    @abc.abstractmethod
    def store_proxy_cert(self, external_user, proxy):
        """ Save the proxy certificate name into oauth2 account """
        return

    # ###########################
    # # Login attempts handling #
    # ###########################

    def register_failed_login(self, username):
        log.critical("auth.register_failed_login: not implemented")
        return True

    def get_failed_login(self, username):
        log.critical("auth.get_failed_login: not implemented")
        return 0
