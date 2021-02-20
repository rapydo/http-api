"""
SECURITY ENDPOINTS CHECK
Add auth checks called /checklogged and /testadmin
"""
import abc
import base64
import re
import sys
from datetime import datetime, timedelta
from enum import Enum
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, TypedDict, Union, cast

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
from restapi.utilities import print_and_exit
from restapi.utilities.globals import mem
from restapi.utilities.logs import Events, log, save_event_log
from restapi.utilities.time import get_now
from restapi.utilities.uuid import getUUID

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALL_ROLES = "all"
ANY_ROLE = "any"
ROLE_DISABLED = "disabled"
DEFAULT_GROUP_NAME = "Default"
DEFAULT_GROUP_DESCR = "Default group"

Payload = Dict[str, Any]
User = Any
Group = Any
RoleObj = Any

DISABLE_UNUSED_CREDENTIALS_AFTER_MIN_TESTNIG_VALUE = 60
MAX_PASSWORD_VALIDITY_MIN_TESTNIG_VALUE = 60
MAX_LOGIN_ATTEMPTS_MIN_TESTING_VALUE = 10


class Token(TypedDict, total=False):
    id: str
    token: str
    token_type: str
    emitted: datetime
    last_access: datetime
    expiration: datetime
    IP: str
    location: str
    user: Optional[User]


class FailedLogin(TypedDict):
    progressive_count: int
    username: str
    date: datetime
    IP: str
    location: str


class Role(Enum):
    ADMIN = "admin_root"
    COORDINATOR = "group_coordinator"
    STAFF = "staff_user"
    USER = "normal_user"


class InvalidToken(BaseException):
    pass


# ##############################################################################
# Utility functions used to adapt security settings to Testable values
def get_timedelta(val: int, min_testing_val: int = 0) -> Optional[timedelta]:

    if val == 0:
        return None

    if TESTING:
        return timedelta(seconds=max(val, min_testing_val))
    # Of course cannot be tested
    return timedelta(days=val)  # pragma: no cover


def get_max_login_attempts(val: int) -> int:

    if TESTING and val:
        # min 10 failures, otherwise normal tests will start to fail
        return max(val, MAX_LOGIN_ATTEMPTS_MIN_TESTING_VALUE)

    return val


# ##############################################################################


class BaseAuthentication(metaclass=abc.ABCMeta):

    """
    An almost abstract class with methods
    to be implemented with a new service
    that aims to store credentials of users and roles.
    """

    # Secret loaded from secret.key file
    JWT_SECRET: Optional[bytes] = None
    # JWT_ALGO = 'HS256'
    # Should be faster on 64bit machines
    JWT_ALGO = "HS512"

    # 1 month in seconds
    DEFAULT_TOKEN_TTL = Env.get_int("AUTH_JWT_TOKEN_TTL", 2_592_000)
    # Grace period before starting to evaluate IP address on token validation
    GRACE_PERIOD = timedelta(seconds=Env.get_int("AUTH_TOKEN_IP_GRACE_PERIOD", 7200))
    SAVE_LAST_ACCESS_EVERY = timedelta(
        seconds=Env.get_int("AUTH_TOKEN_SAVE_FREQUENCY", 60)
    )

    FULL_TOKEN = "f"
    PWD_RESET = "r"
    ACTIVATE_ACCOUNT = "a"
    TOTP = "TOTP"
    MIN_PASSWORD_LENGTH = Env.get_int("AUTH_MIN_PASSWORD_LENGTH", 8)

    SECOND_FACTOR_AUTHENTICATION = Env.get_bool(
        "AUTH_SECOND_FACTOR_AUTHENTICATION", False
    )

    # enabled if explicitly set or for 2FA is enabled
    FORCE_FIRST_PASSWORD_CHANGE = SECOND_FACTOR_AUTHENTICATION or Env.get_bool(
        "AUTH_FORCE_FIRST_PASSWORD_CHANGE", False
    )

    # enabled if explicitly set or for 2FA is enabled
    VERIFY_PASSWORD_STRENGTH = SECOND_FACTOR_AUTHENTICATION or Env.get_bool(
        "AUTH_VERIFY_PASSWORD_STRENGTH", False
    )
    MAX_PASSWORD_VALIDITY: Optional[timedelta] = get_timedelta(
        Env.get_int("AUTH_MAX_PASSWORD_VALIDITY", 0),
        MAX_PASSWORD_VALIDITY_MIN_TESTNIG_VALUE,
    )

    DISABLE_UNUSED_CREDENTIALS_AFTER: Optional[timedelta] = get_timedelta(
        Env.get_int("AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER", 0),
        # min 60 seconds are required when testing
        DISABLE_UNUSED_CREDENTIALS_AFTER_MIN_TESTNIG_VALUE,
    )

    MAX_LOGIN_ATTEMPTS = get_max_login_attempts(
        Env.get_int("AUTH_MAX_LOGIN_ATTEMPTS", 0)
    )

    FAILED_LOGINS_EXPIRATION: timedelta = timedelta(
        seconds=Env.get_int("AUTH_LOGIN_BAN_TIME", 3600)
    )

    default_user: Optional[str] = None
    default_password: Optional[str] = None
    roles: List[str] = []
    roles_data: Dict[str, str] = {}
    default_role: str = Role.USER.value

    # To be stored on DB
    failed_logins: Dict[str, List[FailedLogin]] = {}

    # Executed once by Connector in init_app
    @classmethod
    def module_initialization(cls) -> None:
        cls.load_default_user()
        cls.load_roles()
        cls.import_secret(SECRET_KEY_FILE)

    @staticmethod
    def load_default_user() -> None:

        BaseAuthentication.default_user = Env.get("AUTH_DEFAULT_USERNAME")
        BaseAuthentication.default_password = Env.get("AUTH_DEFAULT_PASSWORD")
        if (
            BaseAuthentication.default_user is None
            or BaseAuthentication.default_password is None
        ):  # pragma: no cover
            print_and_exit("Default credentials are unavailable!")

    @staticmethod
    def load_roles() -> None:
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

    def make_login(self, username: str, password: str) -> Tuple[str, Payload, User]:
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
            self.register_failed_login(username)

            self.log_event(
                Events.failed_login,
                payload={"username": username},
                user=user,
            )

            raise Unauthorized("Invalid access credentials", is_warning=True)

        # Check if Oauth2 is enabled
        if user.authmethod != "credentials":  # pragma: no cover
            raise BadRequest("Invalid authentication method")

        # New hashing algorithm, based on bcrypt
        if self.verify_password(password, user.password):
            # Token expiration is capped by the user expiration date, if set
            payload, full_payload = self.fill_payload(user, expiration=user.expiration)
            token = self.create_token(payload)

            self.log_event(Events.login, user=user)
            return token, full_payload, user

        self.log_event(
            Events.failed_login,
            payload={"username": username},
            user=user,
        )
        self.register_failed_login(username)
        raise Unauthorized("Invalid access credentials", is_warning=True)

    @classmethod
    def import_secret(cls, abs_filename: str) -> None:
        try:
            cls.JWT_SECRET = open(abs_filename, "rb").read()
        except OSError:  # pragma: no cover
            print_and_exit("Jwt secret file {} not found", abs_filename)

    # #####################
    # # Password handling #
    ####################
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

    @staticmethod
    def get_remote_ip() -> str:
        try:
            if forwarded_ips := request.headers.getlist("X-Forwarded-For"):
                # it can be something like: ['IP1, IP2']
                return str(forwarded_ips[-1].split(",")[0].strip())

            if PRODUCTION and not TESTING:  # pragma: no cover
                log.warning(
                    "Production mode is enabled, but X-Forwarded-For header is missing"
                )

            if request.remote_addr:
                return request.remote_addr

        # Raised when get_remote_ip is executed outside request context
        # For example when creating tokens in initialize_testing_environment
        except RuntimeError as e:
            log.debug(e)

        # Mocked IP to prevent tests failures when fn executed outside Flask context
        return "0.0.0.0"

    @staticmethod
    def localize_ip(ip: str) -> Any:

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
    def create_token(cls, payload: Payload) -> str:
        """ Generate a byte token with JWT library to encrypt the payload """
        if cls.JWT_SECRET:
            return jwt.encode(payload, cls.JWT_SECRET, algorithm=cls.JWT_ALGO).decode(
                "ascii"
            )
        else:  # pragma: no cover
            log.critical("Server misconfiguration, missing jwt configuration")
            sys.exit(1)

    def create_temporary_token(
        self, user: User, token_type: str, duration: int = 86400
    ) -> Tuple[str, Payload]:
        # invalidate previous tokens with same token_type
        for t in self.get_tokens(user=user):
            ttype = t.get("token_type")
            if ttype is None:  # pragma: no cover
                continue
            if ttype != token_type:
                continue

            tok = t.get("token")
            if tok and self.invalidate_token(tok):
                log.info("Previous token invalidated: {}", tok)

        expiration = datetime.now(pytz.utc) + timedelta(seconds=duration)
        payload, full_payload = self.fill_payload(
            user, expiration=expiration, token_type=token_type
        )
        token = self.create_token(payload)
        return token, full_payload

    @classmethod
    def unpack_token(cls, token: str, raiseErrors: bool = False) -> Optional[Payload]:

        try:
            if cls.JWT_SECRET:
                return jwt.decode(token, cls.JWT_SECRET, algorithms=[cls.JWT_ALGO])
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

        return None

    @staticmethod
    def unpacked_token(
        valid: bool,
        token: Optional[str] = None,
        jti: Optional[str] = None,
        user: Optional[User] = None,
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[User]]:
        return (valid, token, jti, user)

    def verify_token(
        self,
        token: Optional[str],
        raiseErrors: bool = False,
        token_type: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[User]]:

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

    def fill_payload(
        self,
        user: User,
        expiration: Optional[datetime] = None,
        token_type: Optional[str] = None,
    ) -> Tuple[Payload, Payload]:
        """Informations to store inside the JWT token,
        starting from the user obtained from the current service

        Claim attributes listed here:
        http://blog.apcelent.com/json-web-token-tutorial-example-python.html

        TTL is measured in seconds
        """

        payload = {"user_id": user.uuid, "jti": getUUID()}
        full_payload = payload.copy()

        if not token_type:
            token_type = self.FULL_TOKEN

        short_token = False
        if token_type in (self.PWD_RESET, self.ACTIVATE_ACCOUNT):
            short_token = True
            payload["t"] = token_type

        full_payload["t"] = token_type

        now = datetime.now(pytz.utc)

        if expiration is None:
            expiration = now + timedelta(seconds=self.DEFAULT_TOKEN_TTL)

        full_payload["iat"] = now
        full_payload["nbf"] = now  # you may add a timedelta
        full_payload["exp"] = expiration

        if not short_token:
            payload["iat"] = full_payload["iat"]
            payload["nbf"] = full_payload["nbf"]
            payload["exp"] = full_payload["exp"]

        # first used for encoding
        # second used to store information on backend DB
        return payload, full_payload

    # ##################
    # # Roles handling #
    # ##################
    def verify_roles(
        self,
        user: User,
        roles: Optional[List[Union[str, Role]]],
        required_roles: str = ALL_ROLES,
        warnings: bool = True,
    ) -> bool:

        if not roles:
            return True

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

            log.warning(
                "Expected at least one roles from {}, found none in {}",
                roles,
                current_roles,
            )
            return False

        log.critical("Unknown role authorization requirement: {}", required_roles)
        return False

    @staticmethod
    def custom_user_properties_pre(
        userdata: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        try:
            userdata, extradata = mem.customizer.custom_user_properties_pre(userdata)
        except (RestApiException, DatabaseDuplicatedEntry):  # pragma: no cover
            raise
        except BaseException as e:  # pragma: no cover
            raise BadRequest(f"Unable to pre-customize user properties: {e}")

        if "email" in userdata:
            userdata["email"] = userdata["email"].lower()

        return userdata, extradata

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

    # ###########################
    # # Login attempts handling #
    # ###########################

    @classmethod
    def register_failed_login(cls, username: str) -> None:
        ip = cls.get_remote_ip()
        ip_loc = cls.localize_ip(ip)
        cls.failed_logins.setdefault(username, [])

        count = len(cls.failed_logins[username])
        cls.failed_logins[username].append(
            {
                "progressive_count": count + 1,
                "username": username,
                "date": datetime.now(pytz.utc),
                "IP": ip,
                "location": ip_loc,
            }
        )

    @classmethod
    def get_failed_login(cls, username: str) -> int:

        # username not listed or listed with an empty array
        if not (events := cls.failed_logins.get(username, None)):
            return 0

        # Verify the last event
        last_event = events[-1]
        exp = last_event["date"] + cls.FAILED_LOGINS_EXPIRATION
        if datetime.now(pytz.utc) > exp:
            cls.flush_failed_logins(username)
            return 0

        return last_event["progressive_count"]

    @classmethod
    def flush_failed_logins(cls, username: str) -> None:
        cls.failed_logins.pop(username, None)

    def get_totp_secret(self, user: User) -> str:

        if TESTING:  # pragma: no cover
            if (p := Env.get("AUTH_TESTING_TOTP_HASH")) is not None:
                return p

        if not user.mfa_hash:
            # to be encrypted
            user.mfa_hash = pyotp.random_base32()
            self.save_user(user)

        return cast(str, user.mfa_hash)

    def verify_totp(self, user: User, totp_code: Optional[str]) -> bool:

        if totp_code is None:
            raise Unauthorized("Verification code is missing")
        secret = self.get_totp_secret(user)
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):

            self.log_event(
                Events.failed_login,
                payload={"totp": totp_code},
                user=user,
            )

            self.register_failed_login(user.email)
            raise Unauthorized("Verification code is not valid")

        return True

    def get_qrcode(self, user: User) -> str:

        secret = self.get_totp_secret(user)
        totp = pyotp.TOTP(secret)

        project_name = get_project_configuration("project.title", "No project name")

        otpauth_url = totp.provisioning_uri(project_name)
        qr_url = segno.make(otpauth_url)
        qr_stream = BytesIO()
        qr_url.save(qr_stream, kind="png", scale=5)
        return base64.b64encode(qr_stream.getvalue()).decode("utf-8")

    def verify_password_strength(
        self, pwd: str, old_pwd: Optional[str]
    ) -> Tuple[bool, Optional[str]]:

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

    def change_password(
        self,
        user: User,
        password: str,
        new_password: Optional[str],
        password_confirm: Optional[str],
    ) -> bool:

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

        self.log_event(Events.change_password, user=user)

        for token in self.get_tokens(user=user):
            try:
                self.invalidate_token(token=token["token"])
            except BaseException as e:  # pragma: no cover
                log.critical("Failed to invalidate token {}", e)

        return True

    @classmethod
    def verify_blocked_username(cls, username: str) -> None:

        # We do not count failed logins
        if cls.MAX_LOGIN_ATTEMPTS <= 0:
            return

        # We register failed logins but the user does not reached it yet
        if cls.get_failed_login(username) < cls.MAX_LOGIN_ATTEMPTS:
            return

        cls.log_event(
            Events.refused_login,
            payload={
                "username": username,
                "motivation": "account blocked due to too many failed logins",
            },
        )

        # Dear user, you have exceeded the limit!
        raise Forbidden(
            "Sorry, this account is temporarily blocked "
            "due to the number of failed login attempts."
        )

    @classmethod
    def verify_user_status(cls, user: User) -> None:

        if not user.is_active:

            cls.log_event(
                Events.refused_login,
                payload={"username": user.email, "motivation": "account not active"},
            )

            # Beware, frontend leverages on this exact message,
            # do not modified it without fix also on frontend side
            raise Forbidden("Sorry, this account is not active")

        now: Optional[datetime] = None

        if cls.DISABLE_UNUSED_CREDENTIALS_AFTER and user.last_login:

            if TESTING and user.email == cls.default_user:
                log.info("Default user can't be blocked for inactivity during tests")
            else:
                now = get_now(user.last_login.tzinfo)
                if user.last_login + cls.DISABLE_UNUSED_CREDENTIALS_AFTER < now:
                    cls.log_event(
                        Events.refused_login,
                        payload={
                            "username": user.email,
                            "motivation": "account blocked due to inactivity",
                        },
                    )
                    raise Forbidden("Sorry, this account is blocked for inactivity")

        if user.expiration:
            # Reuse the now instance, if previously inizialized
            # tzinfo should be the same for both last_login and expiration fields
            if not now:
                now = get_now(user.expiration.tzinfo)

            if user.expiration < now:
                cls.log_event(
                    Events.refused_login,
                    payload={"username": user.email, "motivation": "account expired"},
                )
                raise Forbidden("Sorry, this account is expired")

    # Mostly copied in definition.py
    @classmethod
    def log_event(
        cls,
        event: Events,
        target: Optional[Any] = None,
        payload: Optional[Dict[str, Any]] = None,
        user: Optional[Any] = None,
    ) -> None:

        save_event_log(
            event=event,
            payload=payload,
            user=user,
            target=target,
            ip=cls.get_remote_ip(),
        )

    def init_auth_db(self, options):

        self.init_roles()

        default_group = self.init_groups(force=options.get("force_group", False))

        self.init_users(
            default_group, self.roles, force=options.get("force_user", False)
        )

    def init_roles(self) -> None:
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

    def init_groups(self, force):

        create = False
        update = False

        default_group = self.get_group(name=DEFAULT_GROUP_NAME)

        # If there are no groups, let's create the default group
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
            # Added to make the life easier to mypy... but cannot be False
            if default_group:
                default_group.shortname = DEFAULT_GROUP_NAME
                default_group.fullname = DEFAULT_GROUP_DESCR
            else:  # pragma: no cover
                log.critical("Default group not found")
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

        if self.FORCE_FIRST_PASSWORD_CHANGE:
            last_password_change = None
        else:
            last_password_change = datetime.now(pytz.utc)

        if create:

            default_user = self.create_user(
                {
                    "email": self.default_user,
                    "name": "Default",
                    "surname": "User",
                    "password": self.default_password,
                    "last_password_change": last_password_change,
                },
                roles=roles,
            )
            self.add_user_to_group(default_user, default_group)
            # This is required to execute the commit on sqlalchemy...
            self.save_user(default_user)
            log.info("Injected default user")

        elif update:
            # Added to make the life easier to mypy... but cannot be False
            if default_user:
                log.info("Default user already exists, updating")
                default_user.email = self.default_user
                default_user.name = "Default"
                default_user.surname = "User"
                default_user.password = self.get_password_hash(self.default_password)
                default_user.last_password_change = last_password_change
                self.link_roles(default_user, roles)
                self.add_user_to_group(default_user, default_group)
                self.save_user(default_user)
            else:  # pragma: no cover
                log.critical("Default user not found")
        elif default_user:
            log.info("Default user already exists")
        else:
            log.info("Default user does not exist but other users do")

        # Assign all users without a group to the default group
        for user in self.get_users():
            if not user.belongs_to:
                self.add_user_to_group(user, default_group)

        return default_user

    # ########################
    # #  Abstract methods  # #
    # ########################

    @abc.abstractmethod
    def get_user(
        self, username: Optional[str] = None, user_id: Optional[str] = None
    ) -> Optional[User]:  # pragma: no cover
        """
        How to retrieve a single user from the current authentication db,
        based on the unique username or the user_id
        return None if no filter parameter is given
        """
        ...

    @abc.abstractmethod
    def get_users(self) -> List[User]:  # pragma: no cover
        """
        How to retrieve a list of all users from the current authentication db
        """
        ...

    @abc.abstractmethod
    def save_user(self, user: User) -> bool:  # pragma: no cover
        # log.error("Users are not saved in base authentication")
        ...

    @abc.abstractmethod
    def delete_user(self, user: User) -> bool:  # pragma: no cover
        # log.error("Users are not deleted in base authentication")
        ...

    @abc.abstractmethod
    def get_group(
        self, group_id: Optional[str] = None, name: Optional[str] = None
    ) -> Optional[Group]:  # pragma: no cover
        """
        How to retrieve a single group from the current authentication db,
        """
        ...

    @abc.abstractmethod
    def get_groups(self) -> List[Group]:  # pragma: no cover
        """
        How to retrieve groups list from the current authentication db,
        """
        ...

    @abc.abstractmethod
    def save_group(self, group: Group) -> bool:  # pragma: no cover
        ...

    @abc.abstractmethod
    def delete_group(self, group: Group) -> bool:  # pragma: no cover
        ...

    @abc.abstractmethod
    def get_tokens(
        self,
        user: Optional[User] = None,
        token_jti: Optional[str] = None,
        get_all: bool = False,
    ) -> List[Token]:  # pragma: no cover
        """
        Return the list of tokens
        """
        ...

    @abc.abstractmethod
    def verify_token_validity(self, jti: str, user: User) -> bool:  # pragma: no cover
        """
        This method MUST be implemented by specific Authentication Methods
        to add more specific validation contraints
        """
        ...

    @abc.abstractmethod  # pragma: no cover
    def save_token(
        self, user: User, token: str, payload: Payload, token_type: Optional[str] = None
    ) -> None:
        log.debug("Tokens is not saved in base authentication")

    @abc.abstractmethod
    def invalidate_token(self, token: str) -> bool:  # pragma: no cover
        """
        With this method the specified token must be invalidated
        as expected after a user logout
        """
        ...

    @abc.abstractmethod
    def get_roles(self) -> List[RoleObj]:  # pragma: no cover
        """
        How to retrieve all the roles
        """
        ...

    @abc.abstractmethod
    def get_roles_from_user(
        self, user: Optional[User]
    ) -> List[str]:  # pragma: no cover
        """
        Retrieve roles from a user object from the current auth service
        """
        ...

    @abc.abstractmethod
    def create_role(self, name: str, description: str) -> None:  # pragma: no cover
        """
        A method to create a new role
        """
        ...

    @abc.abstractmethod
    def save_role(self, role: RoleObj) -> bool:  # pragma: no cover
        ...

    # ################
    # # Create Users #
    # ################
    @abc.abstractmethod
    def create_user(
        self, userdata: Dict[str, Any], roles: List[str]
    ) -> User:  # pragma: no cover
        """
        A method to create a new user
        """
        ...

    @abc.abstractmethod
    def link_roles(self, user: User, roles: List[str]) -> None:  # pragma: no cover
        """
        A method to assign roles to a user
        """
        ...

    @abc.abstractmethod
    def create_group(self, groupdata: Dict[str, Any]) -> Group:  # pragma: no cover
        """
        A method to create a new group
        """
        ...

    @abc.abstractmethod
    def add_user_to_group(self, user: User, group: Group) -> None:  # pragma: no cover
        """
        Expand the group.members -> user relationship
        """
        ...
