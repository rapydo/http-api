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

from restapi.confs import TESTING
from restapi.services.detect import Detector
from restapi.exceptions import RestApiException
from restapi.confs import PRODUCTION, CUSTOM_PACKAGE, get_project_configuration
from restapi.confs.attributes import ALL_ROLES, ANY_ROLE

from restapi.utilities.meta import Meta
from restapi.utilities.uuid import getUUID
from restapi.utilities.globals import mem
from restapi.utilities.logs import log

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

NULL_IP = "0.0.0.0"


class InvalidToken(BaseException):
    pass


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

    # 1 month in seconds
    DEFAULT_TOKEN_TTL = float(Detector.get_global_var('AUTH_JWT_TOKEN_TTL', 2592000))
    GRACE_PERIOD = 7200  # 2 hours in seconds

    FULL_TOKEN = "f"
    PWD_RESET = "r"
    ACTIVATE_ACCOUNT = "a"

    def __init__(self):
        self.myinit()
        # Create variables to be fulfilled by the authentication decorator
        self._token = None
        self._jti = None
        self._user = None

    @classmethod
    def myinit(cls):

        credentials = get_project_configuration("variables.backend.credentials")

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

    def make_login(self, username, password):
        """ The method which will check if credentials are good to go """

        try:
            user = self.get_user_object(username=username)
        except ValueError as e:
            # SqlAlchemy can raise the following error:
            # A string literal cannot contain NUL (0x00) characters.
            log.error(e)
            raise RestApiException(
                "Invalid input received",
                status_code=400,
            )
        except BaseException as e:
            log.error("Unable to connect to auth backend\n[{}] {}", type(e), e)
            # log.critical("Please reinitialize backend tables")

            raise RestApiException(
                "Unable to connect to auth backend",
                status_code=500,
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
            payload, full_payload = self.fill_payload(user)
            token = self.create_token(payload)
            return token, full_payload

        # old hashing; deprecated since 0.7.2. Removed me in a near future!!
        # Probably when ALL users will be converted... uhm... never?? :-D
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
        if not password:
            raise RestApiException("Invalid password", status_code=401)
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
    def get_user_object(self, username=None, payload=None):  # pragma: no cover
        """
        How to retrieve the user from the current service,
        based on the unique username given, or from the content of the token
        """
        return

    @abc.abstractmethod
    def get_users(self, user_id=None):  # pragma: no cover
        """
        How to retrieve users list from the current service,
        Optionally filter by the unique uuid given
        """
        return

    @abc.abstractmethod
    def get_tokens(self, user=None, token_jti=None, get_all=False):  # pragma: no cover
        """
            Return the list of tokens
        """
        return

    @staticmethod
    def get_remote_ip():  # pragma: no cover
        try:
            if 'X-Forwarded-For' in request.headers:
                forwarded_ips = request.headers['X-Forwarded-For']
                ip = current_app.wsgi_app.get_remote_addr([forwarded_ips])
                return ip
            elif PRODUCTION:
                log.warning("Server in production X-Forwarded-For header is missing")

            ip = request.remote_addr
            return ip
        except RuntimeError as e:
            # When executed from tests it raises
            # RuntimeError: Working outside of request context.
            # Just mock an IP address (NULL_IP = 0.0.0.0)
            if TESTING:
                return NULL_IP
            raise e

    @staticmethod
    def localize_ip(ip):

        if ip is None:
            return None

        try:
            data = mem.geo_reader.get(ip)

            if data is None:
                return None

            if 'country' in data:
                try:
                    c = data['country']['names']['en']
                    return c
                except BaseException:
                    log.error("Missing country.names.en in {}", data)
                    return None
            if 'continent' in data:  # pragma: no cover
                try:
                    c = data['continent']['names']['en']
                    return c

                except BaseException:
                    log.error("Missing continent.names.en in {}", data)
                    return None
            return None
        except BaseException as e:
            log.error("{}. Input was {}", e, ip)

        return None

    # ###################
    # # Tokens handling #
    # ###################
    def create_token(self, payload):
        """ Generate a byte token with JWT library to encrypt the payload """
        self._user = self.get_user_object(payload=payload)
        encode = jwt.encode(payload, self.JWT_SECRET, algorithm=self.JWT_ALGO).decode(
            'ascii'
        )

        return encode

    def create_temporary_token(self, user, token_type, duration=86400):
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

        expiration = timedelta(seconds=duration)
        payload, full_payload = self.fill_payload(
            user, expiration=expiration, token_type=token_type)
        token = self.create_token(payload)
        return token, full_payload

    @abc.abstractmethod
    def verify_token_validity(self, jti, user):  # pragma: no cover
        """
            This method MUST be implemented by specific Authentication Methods
            to add more specific validation contraints
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

        # Force cleaning
        self._token = None
        self._jti = None
        self._user = None

        if token is None:
            if raiseErrors:
                raise InvalidToken("Missing token")
            return False

        # Decode the current token
        payload = self.unpack_token(token, raiseErrors=raiseErrors)
        if payload is None:
            if raiseErrors:
                raise InvalidToken("Invalid payload")
            return False

        payload_type = payload.get("t", self.FULL_TOKEN)

        if token_type is None:
            token_type = self.FULL_TOKEN

        if token_type != payload_type:
            log.error("Invalid token type {}, required: {}", payload_type, token_type)
            if raiseErrors:
                raise InvalidToken("Invalid token type")
            return False

        # Get the user from payload
        user = self.get_user_object(payload=payload)
        if user is None:
            if raiseErrors:
                raise InvalidToken("No user from payload")
            return False

        # implemented from the specific db services
        if not self.verify_token_validity(jti=payload['jti'], user=user):
            if raiseErrors:
                raise InvalidToken("Token is not valid")
            return False

        log.verbose("User authorized")

        self._token = token
        self._jti = payload['jti']
        self._user = user
        return True

    @abc.abstractmethod  # pragma: no cover
    def save_token(self, user, token, payload, token_type=None):
        log.debug("Token is not saved in base authentication")

    @abc.abstractmethod
    def save_user(self, user):  # pragma: no cover
        log.debug("User is not saved in base authentication")

    @abc.abstractmethod
    def invalidate_token(self, token):  # pragma: no cover
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

        payload = {'user_id': userobj.uuid, 'jti': getUUID()}
        full_payload = payload.copy()

        if not token_type:
            token_type = self.FULL_TOKEN

        short_token = False
        if token_type in (self.PWD_RESET, self.ACTIVATE_ACCOUNT):
            short_token = True
            payload["t"] = token_type

        full_payload["t"] = token_type

        if expiration is None:
            expiration = timedelta(seconds=self.DEFAULT_TOKEN_TTL)
        now = datetime.now(pytz.utc)
        full_payload['iat'] = now
        full_payload['nbf'] = now  # you can add a timedelta
        full_payload['exp'] = now + expiration

        if not short_token:
            now = datetime.now(pytz.utc)
            payload['iat'] = full_payload['iat']
            payload['nbf'] = full_payload['nbf']
            payload['exp'] = full_payload['exp']

        # first used for encoding
        # second used to store information on backend DB
        return payload, full_payload

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
    def get_roles(self):  # pragma: no cover
        """
        How to retrieve all the roles
        """
        return

    @abc.abstractmethod
    def get_roles_from_user(self, userobj=None):  # pragma: no cover
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
    def init_users_and_roles(self):  # pragma: no cover
        """
        Create roles and a user if no one exists.
        """
        return

    @staticmethod
    def custom_user_properties(userdata):
        module_path = "{}.initialization.initialization".format(CUSTOM_PACKAGE)
        module = Meta.get_module_from_string(module_path)

        CustomizerClass = Meta.get_class_from_string(
            'Customizer',
            module,
            skip_error=True
        )
        if CustomizerClass is None:
            log.debug("No user properties customizer available")
        else:
            try:
                userdata = CustomizerClass().custom_user_properties(userdata)
            except BaseException as e:
                log.error("Unable to customize user properties: {}", e)

        if "email" in userdata:
            userdata["email"] = userdata["email"].lower()

        return userdata

    def custom_post_handle_user_input(self, user_node, input_data):
        module_path = "{}.initialization.initialization".format(CUSTOM_PACKAGE)
        module = Meta.get_module_from_string(module_path)

        CustomizerClass = Meta.get_class_from_string(
            'Customizer',
            module,
            skip_error=True
        )
        if CustomizerClass is None:
            log.debug("No user properties customizer available")
        else:
            try:
                CustomizerClass().custom_post_handle_user_input(
                    self,
                    user_node,
                    input_data
                )
            except BaseException as e:
                log.error("Unable to customize user properties: {}", e)

    # ################
    # # Create Users #
    # ################
    @abc.abstractmethod
    def create_user(self, userdata, roles):  # pragma: no cover
        """
        A method to create a new user following some standards.
        - The user should be at least associated to the default (basic) role
        - More to come
        """
        return

    @abc.abstractmethod
    def link_roles(self, user, roles):  # pragma: no cover
        """
        A method to assign roles to a user
        """
        return

    # ###########################
    # # Login attempts handling #
    # ###########################

    @staticmethod
    def register_failed_login(username):
        log.critical("auth.register_failed_login: not implemented")
        return True

    @staticmethod
    def get_failed_login(username):
        log.critical("auth.get_failed_login: not implemented")
        return 0
