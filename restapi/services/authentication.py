"""
SECURITY ENDPOINTS CHECK
Add auth checks called /checklogged and /testadmin
"""

import abc
import base64
import hashlib
import hmac
import re
from datetime import datetime, timedelta
from enum import Enum
from io import BytesIO
from typing import Dict, List, Optional, cast

import jwt
import pyotp  # TOTP generation
import pytz
import segno  # QR Code generation
from flask import request
from jwt.exceptions import ExpiredSignatureError, ImmatureSignatureError
from passlib.context import CryptContext

from restapi.config import (
    PRODUCTION,
    SECRET_KEY_FILE,
    TESTING,
    get_project_configuration,
)
from restapi.env import Env
from restapi.exceptions import (
    BadRequest,
    Conflict,
    DatabaseDuplicatedEntry,
    Forbidden,
    RestApiException,
    ServiceUnavailable,
    Unauthorized,
)
from restapi.services.detect import Detector
from restapi.utilities import print_and_exit
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.time import get_now
from restapi.utilities.uuid import getUUID

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

NULL_IP = "0.0.0.0"
ALL_ROLES = "all"
ANY_ROLE = "any"
ROLE_DISABLED = "disabled"


class Role(Enum):
    ADMIN = "admin_root"
    COORDINATOR = "group_coordinator"
    STAFF = "staff_user"
    USER = "normal_user"


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
    JWT_ALGO = "HS512"

    # 1 month in seconds
    DEFAULT_TOKEN_TTL = Env.get_int("AUTH_JWT_TOKEN_TTL", 2_592_000)
    GRACE_PERIOD = timedelta(seconds=7200)  # 2 hours in seconds
    SAVE_LAST_ACCESS_EVERY = timedelta(
        seconds=Env.get_int("AUTH_TOKEN_SAVE_FREQUENCY", 60)
    )

    FULL_TOKEN = "f"
    PWD_RESET = "r"
    ACTIVATE_ACCOUNT = "a"
    TOTP = "TOTP"
    MIN_PASSWORD_LENGTH = 8
    FORCE_FIRST_PASSWORD_CHANGE = False
    VERIFY_PASSWORD_STRENGTH = False
    MAX_PASSWORD_VALIDITY: Optional[timedelta] = None
    DISABLE_UNUSED_CREDENTIALS_AFTER: Optional[timedelta] = None
    REGISTER_FAILED_LOGIN = False
    MAX_LOGIN_ATTEMPTS = 0
    SECOND_FACTOR_AUTHENTICATION: Optional[str] = None

    default_user: Optional[str] = None
    default_password: Optional[str] = None
    roles: List[str] = []
    roles_data: Dict[str, str] = {}
    default_role: Optional[str] = None

    # Executed once by Detector in init_services
    @classmethod
    def module_initialization(cls) -> None:
        cls.load_default_user()
        cls.load_roles()
        cls.import_secret(SECRET_KEY_FILE)

        variables = Env.load_variables_group(prefix="auth")

        cls.MIN_PASSWORD_LENGTH = Env.to_int(variables.get("min_password_length", 8))
        cls.FORCE_FIRST_PASSWORD_CHANGE = Env.to_bool(
            variables.get("force_first_password_change")
        )
        cls.VERIFY_PASSWORD_STRENGTH = Env.to_bool(
            variables.get("verify_password_strength")
        )
        if val := Env.to_int(variables.get("max_password_validity", 0)):
            if TESTING:
                cls.MAX_PASSWORD_VALIDITY = timedelta(seconds=val)
            # Of course cannot be tested
            else:  # pragma: no cover
                cls.MAX_PASSWORD_VALIDITY = timedelta(days=val)

        if val := Env.to_int(variables.get("disable_unused_credentials_after", 0)):
            cls.DISABLE_UNUSED_CREDENTIALS_AFTER = timedelta(days=val)

        cls.REGISTER_FAILED_LOGIN = Env.to_bool(variables.get("register_failed_login"))
        cls.MAX_LOGIN_ATTEMPTS = Env.to_int(variables.get("max_login_attempts", 0))
        cls.SECOND_FACTOR_AUTHENTICATION = variables.get("second_factor_authentication")

        if cls.SECOND_FACTOR_AUTHENTICATION == "None":
            cls.SECOND_FACTOR_AUTHENTICATION = None
        elif not cls.FORCE_FIRST_PASSWORD_CHANGE:
            log.error(
                "{} cannot be enabled if AUTH_FORCE_FIRST_PASSWORD_CHANGE is False",
                cls.SECOND_FACTOR_AUTHENTICATION,
            )
            cls.SECOND_FACTOR_AUTHENTICATION = None

    @staticmethod
    def load_default_user():

        BaseAuthentication.default_user = Env.get("AUTH_DEFAULT_USERNAME")
        BaseAuthentication.default_password = Env.get("AUTH_DEFAULT_PASSWORD")
        if (
            BaseAuthentication.default_user is None
            or BaseAuthentication.default_password is None
        ):  # pragma: no cover
            print_and_exit("Default credentials are unavailable!")

    @staticmethod
    def load_roles():
        BaseAuthentication.roles_data = get_project_configuration(
            "variables.roles"
        ).copy()
        if not BaseAuthentication.roles_data:  # pragma: no cover
            print_and_exit("No roles configured")

        BaseAuthentication.default_role = BaseAuthentication.roles_data.pop("default")

        BaseAuthentication.roles = []
        for role, description in BaseAuthentication.roles_data.items():
            if description != ROLE_DISABLED:
                BaseAuthentication.roles.append(role)

        if not BaseAuthentication.default_role:  # pragma: no cover
            print_and_exit(
                "Default role {} not available!", BaseAuthentication.default_role
            )

    def failed_login(self, username):
        # if self.REGISTER_FAILED_LOGIN and username is not None:
        #     self.register_failed_login(username)

        raise Unauthorized("Invalid username or password", is_warning=True)

    def make_login(self, username, password):
        """ The method which will check if credentials are good to go """

        try:
            user = self.get_user(username=username)
        except ValueError as e:  # pragma: no cover
            # SqlAlchemy can raise the following error:
            # A string literal cannot contain NUL (0x00) characters.
            log.error(e)
            raise BadRequest("Invalid input received")
        except BaseException as e:  # pragma: no cover
            log.error("Unable to connect to auth backend\n[{}] {}", type(e), e)

            raise ServiceUnavailable("Unable to connect to auth backend")

        if user is None:
            # this can raise exceptions in case of errors
            self.failed_login(username)

        # Check if Oauth2 is enabled
        if user.authmethod != "credentials":  # pragma: no cover
            raise BadRequest("Invalid authentication method")

        # New hashing algorithm, based on bcrypt
        if self.verify_password(password, user.password):
            payload, full_payload = self.fill_payload(user)
            token = self.create_token(payload)

            if token is None:
                # this can raise exceptions in case of errors
                self.failed_login(username)

            return token, full_payload, user

        # old hashing; deprecated since 0.7.2. Removed me in a near future!!
        # Probably when ALL users will be converted... uhm... never?? :-D
        if self.check_old_password(user.password, password):  # pragma: no cover
            log.warning(
                "Old password encoding for user {}, automatic convertion", user.email
            )

            now = datetime.now(pytz.utc)
            user.password = BaseAuthentication.get_password_hash(password)
            user.last_password_change = now
            self.save_user(user)

            return self.make_login(username, password)

        self.failed_login(username)

    @classmethod
    def import_secret(cls, abs_filename):
        try:
            cls.JWT_SECRET = open(abs_filename, "rb").read()
            return cls.JWT_SECRET
        except OSError:  # pragma: no cover
            print_and_exit("Jwt secret file {} not found", abs_filename)

    # #####################
    # # Password handling #
    ####################
    # Old hashing, deprecated since 0.7.2
    @staticmethod
    def encode_string(string):
        """ Encodes a string to bytes, if it isn't already. """
        if isinstance(string, str):
            string = string.encode("utf-8")
        return string

    # Old hashing. Deprecated since 0.7.2
    @staticmethod
    def hash_password(password, salt="Unknown"):
        """Original source:
        # https://github.com/mattupstate/flask-security
        #    /blob/develop/flask_security/utils.py#L110
        """

        h = hmac.new(
            BaseAuthentication.encode_string(salt),
            BaseAuthentication.encode_string(password),
            hashlib.sha512,
        )
        return base64.b64encode(h.digest()).decode("ascii")

    # Old hashing. Deprecated since 0.7.2
    @staticmethod
    def check_old_password(hashed_password, password):
        return hashed_password == BaseAuthentication.hash_password(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        try:
            return cast(bool, pwd_context.verify(plain_password, hashed_password))
        except ValueError as e:  # pragma: no cover
            log.error(e)

            return False

    @staticmethod
    def get_password_hash(password):
        if not password:
            raise Unauthorized("Invalid password")
        return pwd_context.hash(password)

    # ########################
    # # Retrieve information #
    # ########################

    @abc.abstractmethod
    def get_user(self, username=None, user_id=None):  # pragma: no cover
        """
        How to retrieve a single user from the current authentication db,
        based on the unique username or the user_id
        return None if no filter parameter is given
        """
        return

    @abc.abstractmethod
    def get_users(self):  # pragma: no cover
        """
        How to retrieve a list of all users from the current authentication db,
        """
        return

    @abc.abstractmethod
    def save_user(self, user):  # pragma: no cover
        log.error("Users are not saved in base authentication")
        return False

    @abc.abstractmethod
    def delete_user(self, user):  # pragma: no cover
        log.error("Users are not deleted in base authentication")
        return False

    @abc.abstractmethod
    def get_group(self, group_id=None, name=None):  # pragma: no cover
        """
        How to retrieve a single group from the current authentication db,
        """
        return

    @abc.abstractmethod
    def get_groups(self):  # pragma: no cover
        """
        How to retrieve groups list from the current authentication db,
        """
        return

    @abc.abstractmethod
    def save_group(self, group):  # pragma: no cover
        log.error("Groups are not saved in base authentication")
        return False

    @abc.abstractmethod
    def delete_group(self, group):  # pragma: no cover
        log.error("Groups are not deleted in base authentication")
        return False

    @abc.abstractmethod
    def get_tokens(self, user=None, token_jti=None, get_all=False):  # pragma: no cover
        """
        Return the list of tokens
        """
        return

    @staticmethod
    def get_remote_ip():  # pragma: no cover
        try:
            if forwarded_ips := request.headers.getlist("X-Forwarded-For"):
                # it can be something like: ['IP1, IP2']
                return forwarded_ips[-1].split(",")[0].strip()

            if PRODUCTION and not TESTING:
                log.warning(
                    "Production mode is enabled, but X-Forwarded-For header is missing"
                )

            return request.remote_addr
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

            if "country" in data:
                try:
                    c = data["country"]["names"]["en"]
                    return c
                except BaseException:  # pragma: no cover
                    log.error("Missing country.names.en in {}", data)
                    return None
            if "continent" in data:  # pragma: no cover
                try:
                    c = data["continent"]["names"]["en"]
                    return c

                except BaseException:
                    log.error("Missing continent.names.en in {}", data)
                    return None
            return None  # pragma: no cover
        except BaseException as e:
            log.error("{}. Input was {}", e, ip)

        return None

    # ###################
    # # Tokens handling #
    # ###################
    @classmethod
    def create_token(cls, payload):
        """ Generate a byte token with JWT library to encrypt the payload """
        if cls.JWT_SECRET:
            return jwt.encode(payload, cls.JWT_SECRET, algorithm=cls.JWT_ALGO).decode(
                "ascii"
            )
        print_and_exit(  # pragma: no cover
            "Server misconfiguration, missing jwt configuration"
        )

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
            user, expiration=expiration, token_type=token_type
        )
        token = self.create_token(payload)
        return token, full_payload

    @abc.abstractmethod
    def verify_token_validity(self, jti, user):  # pragma: no cover
        """
        This method MUST be implemented by specific Authentication Methods
        to add more specific validation contraints
        """
        return

    @classmethod
    def unpack_token(cls, token, raiseErrors=False):

        payload = None
        try:
            if cls.JWT_SECRET:
                payload = jwt.decode(token, cls.JWT_SECRET, algorithms=[cls.JWT_ALGO])
            else:
                print_and_exit(  # pragma: no cover
                    "Server misconfiguration, missing jwt configuration"
                )
        # now > exp
        except ExpiredSignatureError as e:
            # should this token be invalidated into the DB?
            if raiseErrors:
                raise e
            else:
                log.info("Unable to decode JWT token. {}", e)
        # now < nbf
        except ImmatureSignatureError as e:
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

    @staticmethod
    def unpacked_token(valid, token=None, jti=None, user=None):
        return (valid, token, jti, user)

    def verify_token(self, token, raiseErrors=False, token_type=None):

        if token is None:
            if raiseErrors:
                raise InvalidToken("Missing token")
            return self.unpacked_token(False)

        # Decode the current token
        payload = self.unpack_token(token, raiseErrors=raiseErrors)
        if payload is None:
            if raiseErrors:
                raise InvalidToken("Invalid payload")
            return self.unpacked_token(False)

        payload_type = payload.get("t", self.FULL_TOKEN)

        if token_type is None:
            token_type = self.FULL_TOKEN

        if token_type != payload_type:
            log.error("Invalid token type {}, required: {}", payload_type, token_type)
            if raiseErrors:
                raise InvalidToken("Invalid token type")
            return self.unpacked_token(False)

        # Get the user from payload
        user = self.get_user(user_id=payload.get("user_id"))
        if user is None:
            if raiseErrors:
                raise InvalidToken("No user from payload")
            return self.unpacked_token(False)

        # implemented from the specific db services
        if not self.verify_token_validity(jti=payload["jti"], user=user):
            if raiseErrors:
                raise InvalidToken("Token is not valid")
            return self.unpacked_token(False)

        log.debug("User {} authorized", user.email)

        return self.unpacked_token(True, token=token, jti=payload["jti"], user=user)

    @abc.abstractmethod  # pragma: no cover
    def save_token(self, user, token, payload, token_type=None):
        log.debug("Tokens is not saved in base authentication")

    @abc.abstractmethod
    def invalidate_token(self, token):  # pragma: no cover
        """
        With this method the specified token must be invalidated
        as expected after a user logout
        """
        return

    def fill_payload(self, userobj, expiration=None, token_type=None):
        """Informations to store inside the JWT token,
        starting from the user obtained from the current service

        Claim attributes listed here:
        http://blog.apcelent.com/json-web-token-tutorial-example-python.html

        TTL is measured in seconds
        """

        payload = {"user_id": userobj.uuid, "jti": getUUID()}
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
        full_payload["iat"] = now
        full_payload["nbf"] = now  # you can add a timedelta
        full_payload["exp"] = now + expiration

        if not short_token:
            now = datetime.now(pytz.utc)
            payload["iat"] = full_payload["iat"]
            payload["nbf"] = full_payload["nbf"]
            payload["exp"] = full_payload["exp"]

        # first used for encoding
        # second used to store information on backend DB
        return payload, full_payload

    # ##################
    # # Roles handling #
    # ##################
    def verify_roles(self, user, roles, required_roles=None, warnings=True):

        if not roles:
            return True

        if required_roles is None:
            required_roles = ALL_ROLES

        current_roles = self.get_roles_from_user(user)

        if required_roles == ALL_ROLES:
            for role in roles:
                if isinstance(role, Role):
                    role = role.value

                if role not in current_roles:
                    if warnings:
                        log.warning("Auth role '{}' missing for request", role)
                    return False
            return True

        if required_roles == ANY_ROLE:
            for role in roles:
                if isinstance(role, Role):
                    role = role.value

                if role in current_roles:
                    return True
            return False

        log.critical("Unknown role authorization requirement: {}", required_roles)
        return False

    @abc.abstractmethod
    def get_roles(self):  # pragma: no cover
        """
        How to retrieve all the roles
        """
        return

    @abc.abstractmethod
    def get_roles_from_user(self, userobj):  # pragma: no cover
        """
        Retrieve roles from a user object from the current auth service
        """
        return

    @abc.abstractmethod
    def create_role(self, name, description):  # pragma: no cover
        """
        A method to create a new role
        """
        return

    @abc.abstractmethod
    def save_role(self, role):  # pragma: no cover
        log.error("Roles are not saved in base authentication")
        return False

    @staticmethod
    def custom_user_properties_pre(userdata):
        try:
            userdata = mem.customizer.custom_user_properties_pre(userdata)
        except (RestApiException, DatabaseDuplicatedEntry):  # pragma: no cover
            raise
        except BaseException as e:  # pragma: no cover
            raise BadRequest(f"Unable to pre-customize user properties: {e}")

        if "email" in userdata:
            userdata["email"] = userdata["email"].lower()

        return userdata

    @staticmethod
    def custom_user_properties_post(user, userdata, extra_userdata, db):
        try:
            mem.customizer.custom_user_properties_post(
                user, userdata, extra_userdata, db
            )
        except (RestApiException, DatabaseDuplicatedEntry):  # pragma: no cover
            raise
        except BaseException as e:  # pragma: no cover
            raise BadRequest(f"Unable to post-customize user properties: {e}")

        return userdata

    # ################
    # # Create Users #
    # ################
    @abc.abstractmethod
    def create_user(self, userdata, roles):  # pragma: no cover
        """
        A method to create a new user
        """
        return

    @abc.abstractmethod
    def link_roles(self, user, roles):  # pragma: no cover
        """
        A method to assign roles to a user
        """
        return

    @abc.abstractmethod
    def create_group(self, groupdata):  # pragma: no cover
        """
        A method to create a new group
        """
        return

    @abc.abstractmethod
    def add_user_to_group(self, user, group):  # pragma: no cover
        """
        Expand the group.members -> user relationship
        """
        return

    # ###########################
    # # Login attempts handling #
    # ###########################

    # @staticmethod
    # def register_failed_login(username):
    #     log.critical("auth.register_failed_login: not implemented")
    #     return True

    # @staticmethod
    # def get_failed_login(username):
    #     log.critical("auth.get_failed_login: not implemented")
    #     return 0

    @staticmethod
    def get_secret(user):

        return "base32secret3232"
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

    def verify_totp(self, user, totp_code):

        if totp_code is None:
            raise Unauthorized("Invalid verification code")
        secret = self.get_secret(user)
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            # if self.REGISTER_FAILED_LOGIN:
            #     self.register_failed_login(user.email)
            raise Unauthorized("Invalid verification code")

        return True

    @classmethod
    def get_qrcode(cls, user):

        secret = cls.get_secret(user)
        totp = pyotp.TOTP(secret)

        project_name = get_project_configuration("project.title", "No project name")

        otpauth_url = totp.provisioning_uri(project_name)
        qr_url = segno.make(otpauth_url)
        qr_stream = BytesIO()
        qr_url.save(qr_stream, kind="png", scale=5)
        return otpauth_url, base64.b64encode(qr_stream.getvalue()).decode("utf-8")

    def verify_password_strength(self, pwd, old_pwd):

        if old_pwd:
            if pwd == old_pwd:
                return False, "The new password cannot match the previous password"

            # in case old_pwd is a hash
            if self.verify_password(pwd, old_pwd):
                return False, "The new password cannot match the previous password"

        if len(pwd) < self.MIN_PASSWORD_LENGTH:
            MIN = self.MIN_PASSWORD_LENGTH
            return False, f"Password is too short, use at least {MIN} characters"

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
            raise BadRequest("Missing new password")

        if password_confirm is None:
            raise BadRequest("Missing password confirmation")

        if new_password != password_confirm:
            raise Conflict("Your password doesn't match the confirmation")

        if self.VERIFY_PASSWORD_STRENGTH:

            check, msg = self.verify_password_strength(new_password, password)

            if not check:
                raise Conflict(msg)

        user.password = BaseAuthentication.get_password_hash(new_password)
        user.last_password_change = datetime.now(pytz.utc)
        self.save_user(user)

        tokens = self.get_tokens(user=user)
        for token in tokens:
            try:
                self.invalidate_token(token=token["token"])
            except BaseException as e:
                log.critical("Failed to invalidate token {}", e)

        return True

    # def verify_blocked_username(self, username):

    #     if not self.REGISTER_FAILED_LOGIN:
    #         # We do not register failed login
    #         return False
    #     if self.MAX_LOGIN_ATTEMPTS <= 0:
    #         # We register failed login, but we do not set a max num of failures
    #         return False
    #     # FIXME: implement get_failed_login
    #     if self.get_failed_login(username) < self.MAX_LOGIN_ATTEMPTS:
    #         # We register and set a max, but user does not reached it yet
    #         return False
    #     # Dear user, you have exceeded the limit
    #     msg = f"""
    #         Sorry, this account is temporarily blocked due to
    #         more than {self.MAX_LOGIN_ATTEMPTS} failed login attempts.
    #         Try again later"""
    #     raise Unauthorized(msg)

    def verify_blocked_user(self, user):

        if self.DISABLE_UNUSED_CREDENTIALS_AFTER and user.last_login:

            # offset-naive datetime to compare with MySQL
            now = get_now(user.last_login.tzinfo)

            if user.last_login + self.DISABLE_UNUSED_CREDENTIALS_AFTER < now:
                raise Unauthorized("Sorry, this account is blocked for inactivity")

    @staticmethod
    def verify_active_user(user):

        if not user.is_active:
            # Beware, frontend leverages on this exact message,
            # do not modified it without fix also on frontend side
            raise Forbidden("Sorry, this account is not active")

    def init_auth_db(self, options):

        self.init_roles()

        default_group = self.init_groups(force=options.get("force_group", False))

        self.init_users(
            default_group, self.roles, force=options.get("force_user", False)
        )

    def init_roles(self):
        current_roles = {role.name: role for role in self.get_roles()}

        for role_name in self.roles:
            description = self.roles_data.get(role_name, ROLE_DISABLED)
            if r := current_roles.get(role_name):

                if r.description == description:
                    log.info("Role {} already exists", role_name)
                else:
                    log.info("Role {} already exists, updating description", role_name)

                    r.description = description
                    self.save_role(r)

            else:
                log.info("Creating role: {}", role_name)
                self.create_role(name=role_name, description=description)

        for r in current_roles:
            if r not in self.roles:
                log.warning("Unknown role found: {}", r)

        return self.roles

    def init_groups(self, force):

        DEFAULT_GROUP_NAME = "Default"
        DEFAULT_GROUP_DESCR = "Default group"

        create = False
        update = False

        default_group = self.get_group(name=DEFAULT_GROUP_NAME)

        # If there are not groups, let's create the default group
        if not self.get_groups():
            create = True
        # If there are some groups skip group creation in absence of a force flag
        elif force:
            # If force flag is enable, create the default group if missing or update it
            create = default_group is None
            update = default_group is not None

        if create:
            default_group = self.create_group(
                {
                    "shortname": DEFAULT_GROUP_NAME,
                    "fullname": DEFAULT_GROUP_DESCR,
                }
            )
            log.info("Injected default group")
        elif update:
            log.info("Default group already exists, updating")
            default_group.shortname = DEFAULT_GROUP_NAME
            default_group.fullname = DEFAULT_GROUP_DESCR
            self.save_group(default_group)
        elif default_group:
            log.info("Default group already exists")
        else:
            log.info("Default group does not exist but other groups do")

        return default_group

    def init_users(self, default_group, roles, force):

        create = False
        update = False

        default_user = self.get_user(username=self.default_user)

        # If there are no users, let's create the default user
        if not self.get_users():
            create = True
        # If there are some users skip user creation in absence of a force flag
        elif force:
            # If force flag is enable, create the default user if missing or update it
            create = default_user is None
            update = default_user is not None

        if create:
            default_user = self.create_user(
                {
                    "email": self.default_user,
                    "name": "Default",
                    "surname": "User",
                    "password": self.default_password,
                    "last_password_change": datetime.now(pytz.utc),
                },
                roles=roles,
            )
            self.add_user_to_group(default_user, default_group)
            # This is required to execute the commit on sqlalchemy...
            self.save_user(default_user)
            log.info("Injected default user")

        elif update:
            log.info("Default user already exists, updating")
            default_user.email = self.default_user
            default_user.name = "Default"
            default_user.surname = "User"
            default_user.password = self.get_password_hash(self.default_password)
            default_user.last_password_change = datetime.now(pytz.utc)
            self.link_roles(default_user, roles)
            self.add_user_to_group(default_user, default_group)
            self.save_user(default_user)
        elif default_user:
            log.info("Default user already exists")
        else:
            log.info("Default user does not exist but other users do")

        # Assign all users without a group to the default group
        for user in self.get_users():
            if not user.belongs_to:
                self.add_user_to_group(user, default_group)

        return default_user
