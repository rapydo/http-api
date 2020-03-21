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

from passlib.context import CryptContext
from datetime import datetime, timedelta
from flask import current_app, request
from restapi.services.detect import Detector
from restapi.confs import PRODUCTION, CUSTOM_PACKAGE, get_project_configuration
from restapi.attributes import ALL_ROLES, ANY_ROLE
from restapi.utilities.meta import Meta
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.uuid import getUUID
from restapi.utilities.globals import mem

from restapi.utilities.logs import log

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class BaseAuthentication(metaclass=abc.ABCMeta):

    """
    An almost abstract class with methods
    to be implemented with a new service
    that aims to store credentials of users and roles.
    """

    # Secret loaded from secret.key file
    JWT_SECRET = None
    # JWT_ALGO = 'HS256'
    # Should be faster on 64bit machines
    JWT_ALGO = 'HS512'

    FULL_TOKEN = "f"
    PWD_RESET = "r"
    ACTIVATE_ACCOUNT = "a"

    def __init__(self):
        self.myinit()
        # Create variables to be fulfilled by the authentication decorator
        self._token = None
        self._jti = None
        self._user = None
        # Default shortTTL = 2592000     # 1 month in seconds
        self.longTTL = float(Detector.get_global_var('TOKEN_LONG_TTL', 2592000))
        # Default shortTTL = 604800     # 1 week in seconds
        self.shortTTL = float(Detector.get_global_var('TOKEN_SHORT_TTL', 604800))
        self.grace_period = 7200  # 2 hours in seconds

    @classmethod
    def myinit(cls):

        credentials = get_project_configuration("variables.backend.credentials")

        if credentials.get('username') is not None:
            log.exit("Obsolete use of variables.backend.credentials.username")

        if credentials.get('password') is not None:
            log.exit("Obsolete use of variables.backend.credentials.password")

        # cls.default_user = credentials.get('username', None)
        # cls.default_password = credentials.get('password', None)
        cls.default_user = Detector.get_global_var('AUTH_DEFAULT_USERNAME')
        cls.default_password = Detector.get_global_var('AUTH_DEFAULT_PASSWORD')
        if cls.default_user is None or cls.default_password is None:
            log.exit("Default credentials are unavailable!")

        roles = credentials.get('roles', {})
        cls.default_role = roles.get('default')
        cls.role_admin = roles.get('admin')
        cls.default_roles = [roles.get('user'), roles.get('internal'), cls.role_admin]
        if cls.default_role is None or None in cls.default_roles:
            log.exit("Default roles are not available!")

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
            log.error("Unable to connect to auth backend\n[{}] {}", type(e), e)
            # log.critical("Please reinitialize backend tables")
            from restapi.exceptions import RestApiException

            raise RestApiException(
                "Unable to connect to auth backend",
                status_code=hcodes.HTTP_SERVER_ERROR,
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

        # New hashing algorithm, based on bcrypt
        if self.verify_password(password, user.password):
            return self.create_token(self.fill_payload(user))

        # old hashing; since 0.7.2. Removed me in a near future!!
        if self.check_old_password(user.password, password):
            log.warning(
                "Old password encoding for user {}, automatic convertion", user.email)

            now = datetime.now(pytz.utc)
            user.password = BaseAuthentication.get_password_hash(password)
            user.last_password_change = now
            self.save_user(user)

            return self.make_login(username, password)

        return None, None

    # ########################
    # # Configure Secret Key #
    # ########################
    def import_secret(self, abs_filename):
        """
        Load the jwt secret from a file
        """

        try:
            self.JWT_SECRET = open(abs_filename, 'rb').read()
            return self.JWT_SECRET
        except IOError:
            log.exit("Jwt secret file {} not found", abs_filename)

    # #####################
    # # Password handling #
    ####################
    # Old hashing, deprecated since 0.7.2
    @staticmethod
    def encode_string(string):
        """ Encodes a string to bytes, if it isn't already. """
        if isinstance(string, str):
            string = string.encode('utf-8')
        return string

    # Old hashing, deprecated since 0.7.2
    @staticmethod
    def hash_password(password, salt="Unknown"):
        """ Original source:
        # https://github.com/mattupstate/flask-security
        #    /blob/develop/flask_security/utils.py#L110
        """

        h = hmac.new(
            BaseAuthentication.encode_string(salt),
            BaseAuthentication.encode_string(password),
            hashlib.sha512,
        )
        return base64.b64encode(h.digest()).decode('ascii')

    # Old hashing, deprecated since 0.7.2
    @staticmethod
    def check_old_password(hashed_password, password):
        return hashed_password == BaseAuthentication.hash_password(password)

    @staticmethod
    def verify_password(plain_password, hashed_password):
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except ValueError as e:
            log.error(e)

            return False

    @staticmethod
    def get_password_hash(password):
        return pwd_context.hash(password)

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
    def get_users(self, user_id=None):
        """
        How to retrieve users list from the current service,
        Optionally filter by the unique uuid given
        """
        return

    @abc.abstractmethod
    def get_tokens(self, user=None, token_jti=None):
        """
            Return the list of all active tokens
        """
        return

    @staticmethod
    def get_remote_ip():

        if 'X-Forwarded-For' in request.headers:
            forwarded_ips = request.headers['X-Forwarded-For']
            ip = current_app.wsgi_app.get_remote_addr([forwarded_ips])
            return ip
        elif PRODUCTION:
            log.warning("Server in production X-Forwarded-For header is missing")

        ip = request.remote_addr
        return ip

    @staticmethod
    def localize_ip(ip):

        try:
            data = mem.geo_reader.get(ip)

            if data is None:
                return "Unknown"

            # if 'city' in data:
            #     try:
            #         return data['city']['names']['en']
            #     except BaseException:
            #         log.error("Missing city.names.en in {}", data)
            #         return "Unknown city"
            if 'country' in data:
                try:
                    return data['country']['names']['en']
                except BaseException:
                    log.error("Missing country.names.en in {}", data)
                    return "Unknown country"
            if 'continent' in data:
                try:
                    return data['continent']['names']['en']
                except BaseException:
                    log.error("Missing continent.names.en in {}", data)
                    return "Unknown continent"
        except BaseException as e:
            log.error(e)

        return "Unknown"

    # ###################
    # # Tokens handling #
    # ###################
    def create_token(self, payload):
        """ Generate a byte token with JWT library to encrypt the payload """
        self._user = self.get_user_object(payload=payload)
        encode = jwt.encode(payload, self.JWT_SECRET, algorithm=self.JWT_ALGO).decode(
            'ascii'
        )

        return encode, payload['jti']

    def create_temporary_token(self, user, duration=300, token_type=None):
        expiration = timedelta(seconds=duration)
        payload = self.fill_payload(user, expiration=expiration, token_type=token_type)
        return self.create_token(payload)

    def create_reset_token(self, user, token_type, duration=86400):
        # invalidate previous tokens with same token_type
        tokens = self.get_tokens(user=user)
        for t in tokens:
            ttype = t.get("token_type")
            if ttype is None:
                continue
            if ttype != token_type:
                continue

            tok = t.get("token")
            if self.invalidate_token(tok):
                log.info("Previous token invalidated: {}", tok)

        # Generate a new reset token
        new_token, jti = self.create_temporary_token(
            user, duration=duration, token_type=token_type
        )

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
            payload = jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGO])
        # now > exp
        except jwt.exceptions.ExpiredSignatureError as e:
            # should this token be invalidated into the DB?
            if raiseErrors:
                raise e
            else:
                log.info("Unable to decode JWT token. {}", e)
        # now < nbf
        except jwt.exceptions.ImmatureSignatureError as e:
            if raiseErrors:
                raise e
            else:
                log.info("Unable to decode JWT token. {}", e)
        except Exception as e:
            if raiseErrors:
                raise e
            else:
                log.warning("Unable to decode JWT token. {}", e)

        return payload

    def verify_token(self, token, raiseErrors=False, token_type=None):

        # Force token cleaning
        self._user = None

        if token is None:
            return False

        # Decode the current token
        payload = self.unpack_token(token, raiseErrors=raiseErrors)
        if payload is None:
            return False

        payload_type = payload.get("t", self.FULL_TOKEN)

        if token_type is None:
            token_type = self.FULL_TOKEN

        if token_type != payload_type:
            log.error("Invalid token type {}, required: {}", payload_type, token_type)
            return False

        # Get the user from payload
        self._user = self.get_user_object(payload=payload)
        if self._user is None:
            return False

        if not self.verify_token_custom(
            user=self._user, jti=payload['jti'], payload=payload
        ):
            return False
        # e.g. for graph: verify the (token <- user) link

        if not self.refresh_token(payload['jti']):
            return False

        log.verbose("User authorized")

        self._token = token
        self._jti = payload['jti']
        return True

    def save_token(self, user, token, jti, token_type=None):
        log.debug("Token is not saved in base authentication")

    @abc.abstractmethod
    def save_user(self, user):
        log.debug("User is not saved in base authentication")

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

    def fill_payload(self, userobj, expiration=None, token_type=None):
        """ Informations to store inside the JWT token,
        starting from the user obtained from the current service

        Claim attributes listed here:
        http://blog.apcelent.com/json-web-token-tutorial-example-python.html

        TTL is measured in seconds
        """

        if expiration is None:
            expiration = timedelta(seconds=self.longTTL)

        payload = {'user_id': userobj.uuid, 'jti': getUUID()}

        short_jwt = (
            Detector.get_global_var('AUTH_FULL_JWT_PAYLOAD', '').lower() == 'false'
        )

        if token_type is not None:
            if token_type in (self.PWD_RESET, self.ACTIVATE_ACCOUNT):
                short_jwt = True
                payload["t"] = token_type

        if not short_jwt:
            now = datetime.now(pytz.utc)
            nbf = now  # you can add a timedelta
            exp = now + expiration
            payload['iat'] = now
            payload['nbf'] = nbf
            payload['exp'] = exp

        return payload

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
                        log.warning("Auth role '{}' missing for request", role)
                    return False
            return True

        if required_roles == ANY_ROLE:
            for role in roles:
                if role in current_roles:
                    return True
            return False

        log.critical("Unknown role authorization requirement: {}", required_roles)
        return False

    def verify_admin(self):
        """ Check if current user has administration role """
        return self.verify_roles([self.role_admin], warnings=False)

    def verify_local_admin(self):
        return self.verify_roles(["local_admin"], warnings=False)

    @abc.abstractmethod
    def get_roles(self):
        """
        How to retrieve all the roles
        """
        return

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
        module_path = "{}.initialization.initialization".format(CUSTOM_PACKAGE)
        module = Meta.get_module_from_string(module_path)

        meta = Meta()
        Customizer = meta.get_class_from_string('Customizer', module, skip_error=True)
        if Customizer is None:
            log.debug("No user properties customizer available")
        else:
            try:
                userdata = Customizer().custom_user_properties(userdata)
            except BaseException as e:
                log.error("Unable to customize user properties: {}", e)

        if "email" in userdata:
            userdata["email"] = userdata["email"].lower()

        return userdata

    def custom_post_handle_user_input(self, user_node, input_data):
        module_path = "{}.initialization.initialization".format(CUSTOM_PACKAGE)
        module = Meta.get_module_from_string(module_path)

        meta = Meta()
        Customizer = meta.get_class_from_string('Customizer', module, skip_error=True)
        if Customizer is None:
            log.debug("No user properties customizer available")
        else:
            try:
                Customizer().custom_post_handle_user_input(self, user_node, input_data)
            except BaseException as e:
                log.error("Unable to customize user properties: {}", e)

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
    def link_roles(self, user, roles):
        """
        A method to assign roles to a user
        """
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
