import base64
import re
from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    TypedDict,
    Union,
    cast,
)

import jwt
import pyotp
import pytz
import segno
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken as InvalidFernetToken
from flask import request
from glom import glom
from jwt.exceptions import ExpiredSignatureError, ImmatureSignatureError
from passlib.context import CryptContext

from restapi.config import (
    BACKEND_HOSTNAME,
    BOT_HOSTNAME,
    HOST_TYPE,
    JWT_SECRET_FILE,
    PRODUCTION,
    PROXIED_CONNECTION,
    TESTING,
    TOTP_SECRET_FILE,
    get_frontend_url,
    get_project_configuration,
)
from restapi.env import Env
from restapi.exceptions import (
    BadRequest,
    Conflict,
    Forbidden,
    RestApiException,
    ServerError,
    ServiceUnavailable,
    Unauthorized,
)
from restapi.types import Props
from restapi.utilities import print_and_exit
from restapi.utilities.globals import mem
from restapi.utilities.logs import Events, log, save_event_log
from restapi.utilities.time import EPOCH, get_now
from restapi.utilities.uuid import getUUID

# Trick to avoid circular dependencies
if TYPE_CHECKING:  # pragma: no cover
    from restapi.connectors import Connector
User = Any
Group = Any
RoleObj = Any
Login = Any


def import_secret(abs_filename: Path) -> bytes:

    if HOST_TYPE != BACKEND_HOSTNAME and HOST_TYPE != BOT_HOSTNAME:  # pragma: no cover
        return Fernet.generate_key()

    try:
        return open(abs_filename, "rb").read()
    # Can't be covered because it is execute once before the tests...
    except OSError:  # pragma: no cover
        key = Fernet.generate_key()
        with open(abs_filename, "wb") as key_file:
            key_file.write(key)
        abs_filename.chmod(0o400)
        return key


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALL_ROLES = "all"
ANY_ROLE = "any"
ROLE_DISABLED = "disabled"
DEFAULT_GROUP_NAME = "Default"
DEFAULT_GROUP_DESCR = "Default group"

DISABLE_UNUSED_CREDENTIALS_AFTER_MIN_TESTNIG_VALUE = 60
MAX_PASSWORD_VALIDITY_MIN_TESTNIG_VALUE = 60
MAX_LOGIN_ATTEMPTS_MIN_TESTING_VALUE = 10
LOGIN_BAN_TIME_MAX_TESTING_VALUE = 10


# Produced by fill_payload
class Payload(TypedDict, total=False):
    user_id: str
    jti: str
    t: str
    iat: datetime
    nbf: datetime
    exp: datetime


# Produced by unpack_token. Datetimes are converted to int as specified in rfc7519
# https://tools.ietf.org/html/rfc7519#page-10
class DecodedPayload(TypedDict, total=False):
    user_id: str
    jti: str
    t: str
    iat: int
    nbf: int
    exp: int


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


class Role(Enum):
    ADMIN = "admin_root"
    COORDINATOR = "group_coordinator"
    STAFF = "staff_user"
    USER = "normal_user"


class InvalidToken(Exception):
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


def get_login_ban_time(val: int) -> int:

    if TESTING and val:
        # max 10 seconds, otherwise tests will hang
        return min(val, LOGIN_BAN_TIME_MAX_TESTING_VALUE)

    return val


# ##############################################################################


class BaseAuthentication(metaclass=ABCMeta):

    """
    An almost abstract class with methods
    to be implemented with a new service
    that aims to store credentials of users and roles.
    """

    JWT_SECRET: str = import_secret(JWT_SECRET_FILE).decode()
    fernet = Fernet(import_secret(TOTP_SECRET_FILE))

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
    UNLOCK_CREDENTIALS = "u"
    TOTP = "TOTP"
    MIN_PASSWORD_LENGTH = Env.get_int("AUTH_MIN_PASSWORD_LENGTH", 8)

    SECOND_FACTOR_AUTHENTICATION = Env.get_bool(
        "AUTH_SECOND_FACTOR_AUTHENTICATION", False
    )

    TOTP_VALIDITY_WINDOW = Env.get_int("AUTH_TOTP_VALIDITY_WINDOW", 1)

    # enabled if explicitly set or for 2FA is enabled
    FORCE_FIRST_PASSWORD_CHANGE = SECOND_FACTOR_AUTHENTICATION or Env.get_bool(
        "AUTH_FORCE_FIRST_PASSWORD_CHANGE", False
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
        Env.get_int("AUTH_MAX_LOGIN_ATTEMPTS", 8)
    )

    FAILED_LOGINS_EXPIRATION: timedelta = timedelta(
        seconds=get_login_ban_time(Env.get_int("AUTH_LOGIN_BAN_TIME", 3600))
    )

    default_user: Optional[str] = None
    default_password: Optional[str] = None
    roles: List[str] = []
    roles_data: Dict[str, str] = {}
    default_role: str = Role.USER.value

    # This is to let inform mypy about the existence of self.db
    def __init__(self) -> None:  # pragma: no cover
        self.db: "Connector"

    # Executed once by Connector in init_app
    @classmethod
    def module_initialization(cls) -> None:
        cls.load_default_user()
        cls.load_roles()

    @staticmethod
    def load_default_user() -> None:

        BaseAuthentication.default_user = Env.get("AUTH_DEFAULT_USERNAME", "")
        BaseAuthentication.default_password = Env.get("AUTH_DEFAULT_PASSWORD", "")
        if (
            not BaseAuthentication.default_user
            or not BaseAuthentication.default_password
        ):  # pragma: no cover
            print_and_exit("Default credentials are unavailable!")

    @staticmethod
    def load_roles() -> None:

        empty_dict: Dict[str, str] = {}
        BaseAuthentication.roles_data = glom(
            mem.configuration, "variables.roles", default=empty_dict
        ).copy()
        if not BaseAuthentication.roles_data:  # pragma: no cover
            print_and_exit("No roles configured")

        BaseAuthentication.default_role = BaseAuthentication.roles_data.pop(
            "default", ""
        )

        if not BaseAuthentication.default_role:  # pragma: no cover
            print_and_exit("Default role not available!")

        BaseAuthentication.roles = []
        for role, description in BaseAuthentication.roles_data.items():
            if description != ROLE_DISABLED:
                BaseAuthentication.roles.append(role)

    def make_login(self, username: str, password: str) -> Tuple[str, Payload, User]:
        """The method which will check if credentials are good to go"""

        try:
            user = self.get_user(username=username)
        except ValueError as e:  # pragma: no cover
            # SqlAlchemy can raise the following error:
            # A string literal cannot contain NUL (0x00) characters.
            log.error(e)
            raise BadRequest("Invalid input received")
        except Exception as e:  # pragma: no cover
            log.error("Unable to connect to auth backend\n[{}] {}", type(e), e)

            raise ServiceUnavailable("Unable to connect to auth backend")

        if user is None:
            self.register_failed_login(username, user=None)

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

            self.save_login(username, user, failed=False)
            self.log_event(Events.login, user=user)
            return token, full_payload, user

        self.log_event(
            Events.failed_login,
            payload={"username": username},
            user=user,
        )
        self.register_failed_login(username, user=user)
        raise Unauthorized("Invalid access credentials", is_warning=True)

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
    def get_password_hash(password: Optional[str]) -> str:
        if not password:
            raise Unauthorized("Invalid password")
        # CryptContext is no typed.. but this is a string!
        return cast(str, pwd_context.hash(password))

    @staticmethod
    def get_remote_ip(raise_warnings: bool = True) -> str:
        try:

            # Syntax: X-Forwarded-For: <client>, <proxy1>, <proxy2>
            #   <client> The client IP address
            #   <proxy1>, <proxy2> If a request goes through multiple proxies, the
            #        IP addresses of each successive proxy is listed. This means, the
            #        right-most IP address is the IP address of the most recent proxy
            #        and the left-most IP address is the IP address of the originating
            #        client.
            if PROXIED_CONNECTION:
                header_key = "X-Forwarded-For"
                if forwarded_ips := request.headers.getlist(header_key):
                    # it can be something like: ['IP1, IP2']
                    return str(forwarded_ips[0].split(",")[0].strip())
            # Standard (and more secure) way to obtain remote IP
            else:
                header_key = "X-Real-Ip"
                # in testing mode X-Forwarded-For is used
                if real_ip := request.headers.get(header_key):  # pragma: no cover
                    return real_ip

            if raise_warnings and PRODUCTION and not TESTING:  # pragma: no cover
                log.warning(
                    "Production mode is enabled, but {} header is missing", header_key
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
    @lru_cache
    def localize_ip(ip: str) -> Optional[str]:

        try:
            data = mem.geo_reader.get(ip)

            if data is None:
                return None

            if "country" in data:
                try:
                    c = data["country"]["names"]["en"]
                    return c  # type: ignore
                except Exception:  # pragma: no cover
                    log.error("Missing country.names.en in {}", data)
                    return None
            if "continent" in data:  # pragma: no cover
                try:
                    c = data["continent"]["names"]["en"]
                    return c  # type: ignore

                except Exception:
                    log.error("Missing continent.names.en in {}", data)
                    return None
            return None  # pragma: no cover
        except Exception as e:
            log.error("{}. Input was {}", e, ip)

        return None

    # ###################
    # # Tokens handling #
    # ###################
    @classmethod
    def create_token(cls, payload: Payload) -> str:
        """Generate a str token with JWT library to encrypt the payload"""
        return jwt.encode(
            cast(Dict[str, Any], payload), cls.JWT_SECRET, algorithm=cls.JWT_ALGO
        )

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
    def unpack_token(
        cls, token: str, raiseErrors: bool = False
    ) -> Optional[DecodedPayload]:

        try:
            return cast(
                DecodedPayload,
                jwt.decode(token, cls.JWT_SECRET, algorithms=[cls.JWT_ALGO]),
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
                raise InvalidToken("Invalid payload")  # pragma: no cover
            return self.unpacked_token(False)

        payload_type = payload.get("t", self.FULL_TOKEN)

        if token_type is None:
            token_type = self.FULL_TOKEN

        if token_type != payload_type:
            log.error("Invalid token type {}, required: {}", payload_type, token_type)
            if raiseErrors:
                raise InvalidToken("Invalid token type")
            return self.unpacked_token(False)

        user_id = payload.get("user_id")
        # Get the user from payload
        user = self.get_user(user_id=user_id)
        if user is None:
            if raiseErrors:
                raise InvalidToken("No user from payload")
            return self.unpacked_token(False)

        # implemented from the specific db services
        if not self.verify_token_validity(jti=payload["jti"], user=user):
            if raiseErrors:
                raise InvalidToken("Token is not valid")
            return self.unpacked_token(False)

        log.debug("User {} is authorized", user.email)

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

        payload: Payload = {"user_id": user.uuid, "jti": getUUID()}
        full_payload: Payload = payload.copy()

        if not token_type:
            token_type = self.FULL_TOKEN

        short_token = False
        if token_type in (
            self.PWD_RESET,
            self.ACTIVATE_ACCOUNT,
            self.UNLOCK_CREDENTIALS,
        ):
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

    # ###############################
    # #####   Roles handling   ######
    # ###############################
    def is_admin(self, user: User) -> bool:
        """Check if current user has Administration role"""
        return self.verify_roles(user, [Role.ADMIN], warnings=False)

    def is_staff(self, user: User) -> bool:
        """Check if current user has Staff role"""
        return self.verify_roles(user, [Role.STAFF], warnings=False)

    def is_coordinator(self, user: User) -> bool:
        """Check if current user has Coordinator role"""
        return self.verify_roles(user, [Role.COORDINATOR], warnings=False)

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
        except RestApiException:  # pragma: no cover
            raise
        except Exception as e:  # pragma: no cover
            raise BadRequest(f"Unable to pre-customize user properties: {e}")

        if "email" in userdata:
            userdata["email"] = userdata["email"].lower()

        return userdata, extradata

    @staticmethod
    def custom_user_properties_post(
        user: User, userdata: Props, extra_userdata: Props, db: "Connector"
    ) -> Props:
        try:
            mem.customizer.custom_user_properties_post(
                user, userdata, extra_userdata, db
            )
        except RestApiException:  # pragma: no cover
            raise
        except Exception as e:  # pragma: no cover
            raise BadRequest(f"Unable to post-customize user properties: {e}")

        return userdata

    # ###########################
    # # Login attempts handling #
    # ###########################

    def register_failed_login(self, username: str, user: Optional[User]) -> None:

        self.save_login(username, user, failed=True)

        if self.MAX_LOGIN_ATTEMPTS == 0:
            log.debug("Failed login are not considered in this configuration")
            return

        if self.count_failed_login(username) < self.MAX_LOGIN_ATTEMPTS:
            return

        log.error(
            "Reached the maximum number of failed login, account {} is blocked",
            username,
        )

        if user:
            # Import here to prevent circular dependencies
            from restapi.connectors.smtp.notifications import notify_login_block

            unlock_token, payload = self.create_temporary_token(
                user, self.UNLOCK_CREDENTIALS
            )

            self.save_token(
                user, unlock_token, payload, token_type=self.UNLOCK_CREDENTIALS
            )

            server_url = get_frontend_url()

            rt = unlock_token.replace(".", "+")
            url = f"{server_url}/app/login/unlock/{rt}"

            failed_logins = self.get_logins(username, only_unflushed=True)
            notify_login_block(
                user,
                reversed(failed_logins),
                self.FAILED_LOGINS_EXPIRATION.seconds,
                url,
            )

    def count_failed_login(self, username: str) -> int:

        failed_logins = self.get_logins(username, only_unflushed=True)
        if not failed_logins:
            return 0

        last_failed = failed_logins[-1]
        exp = last_failed.date + self.FAILED_LOGINS_EXPIRATION

        if get_now(exp.tzinfo) > exp:
            self.flush_failed_logins(username)
            return 0

        return len(failed_logins)

    def get_totp_secret(self, user: User) -> str:

        if TESTING:  # pragma: no cover
            # TESTING_TOTP_HASH is set by setup-cypress github action
            if p := Env.get("AUTH_TESTING_TOTP_HASH", ""):
                return p

        if not user.mfa_hash:
            random_hash = pyotp.random_base32()
            user.mfa_hash = self.fernet.encrypt(random_hash.encode()).decode()
            self.save_user(user)

        try:
            return self.fernet.decrypt(user.mfa_hash.encode()).decode()
        # to test this exception change the fernet key used to encrypt mfa_hash
        except InvalidFernetToken:
            raise ServerError("Invalid server signature")

    def verify_totp(self, user: User, totp_code: Optional[str]) -> bool:

        if totp_code is None:
            raise Unauthorized("Verification code is missing")
        secret = self.get_totp_secret(user)
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=self.TOTP_VALIDITY_WINDOW):

            self.log_event(
                Events.failed_login,
                payload={"totp": totp_code},
                user=user,
            )

            self.register_failed_login(user.email, user=user)
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
        self, pwd: str, old_pwd: Optional[str], email: str, name: str, surname: str
    ) -> Tuple[bool, str]:

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

        MIN_CONTAINED_LEN = 3
        p_lower = pwd.lower()
        if len(name) > MIN_CONTAINED_LEN and name.lower() in p_lower:
            return False, "Password is too weak, can't contain your name"

        if len(surname) > MIN_CONTAINED_LEN and surname.lower() in p_lower:
            return False, "Password is too weak, can't contain your name"

        cleaner = r"[\.|_]"
        email_clean = re.sub(cleaner, "", email.lower().split("@")[0])
        p_clean = re.sub(cleaner, "", p_lower.lower())

        if len(email_clean) > MIN_CONTAINED_LEN and email_clean in p_clean:
            return False, "Password is too weak, can't contain your email address"

        return True, ""

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

        check, msg = self.verify_password_strength(
            pwd=new_password,
            old_pwd=password,
            email=user.email,
            name=user.name,
            surname=user.surname,
        )

        if not check:
            raise Conflict(msg)

        user.password = BaseAuthentication.get_password_hash(new_password)
        user.last_password_change = datetime.now(pytz.utc)
        self.save_user(user)

        self.log_event(Events.change_password, user=user)

        for token in self.get_tokens(user=user):
            try:
                self.invalidate_token(token=token["token"])
            except Exception as e:  # pragma: no cover
                log.critical("Failed to invalidate token {}", e)

        return True

    def check_password_validity(
        self, user: User, totp_authentication: bool
    ) -> Dict[str, List[str]]:

        # ##################################################
        # Check if something is missing in the authentication and ask additional actions
        # raises exceptions in case of errors

        message: Dict[str, List[str]] = {"actions": [], "errors": []}
        last_pwd_change = user.last_password_change
        if last_pwd_change is None or last_pwd_change == 0:
            last_pwd_change = EPOCH

        if self.FORCE_FIRST_PASSWORD_CHANGE and last_pwd_change == EPOCH:

            message["actions"].append("FIRST LOGIN")
            message["errors"].append("Please change your temporary password")

            self.log_event(Events.password_expired, user=user)

            if totp_authentication:

                message["qr_code"] = [self.get_qrcode(user)]

        elif self.MAX_PASSWORD_VALIDITY:

            valid_until = last_pwd_change + self.MAX_PASSWORD_VALIDITY

            # offset-naive datetime to compare with MySQL
            now = get_now(last_pwd_change.tzinfo)

            expired = last_pwd_change == EPOCH or valid_until < now

            if expired:

                message["actions"].append("PASSWORD EXPIRED")
                message["errors"].append("Your password is expired, please change it")

                self.log_event(Events.password_expired, user=user)

        return message

    def verify_blocked_username(self, username: str) -> None:

        # We do not count failed logins
        if self.MAX_LOGIN_ATTEMPTS <= 0:
            return

        # We register failed logins but the user does not reached it yet
        if self.count_failed_login(username) < self.MAX_LOGIN_ATTEMPTS:
            return

        self.log_event(
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

        try:
            url_path = request.path
        except RuntimeError:
            url_path = "-"

        save_event_log(
            event=event,
            payload=payload,
            user=user,
            target=target,
            ip=cls.get_remote_ip(),
            url=url_path,
        )

    def init_auth_db(self, options: Dict[str, bool]) -> None:

        self.init_roles()

        default_group = self.init_groups(force=options.get("force_group", False))

        self.init_users(
            default_group, self.roles, force=options.get("force_user", False)
        )

    def init_roles(self) -> None:
        current_roles = {role.name: role for role in self.get_roles()}
        role_names = list(self.roles_data.values())

        num_of_roles = len(role_names)
        num_of_unique_roles = len(list(set(role_names)))
        if num_of_roles != num_of_unique_roles:
            print_and_exit("Found duplicated role names: {}", str(sorted(role_names)))

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

    def init_groups(self, force: bool) -> Group:

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

    def init_users(self, default_group: Group, roles: List[str], force: bool) -> User:

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

    @abstractmethod
    def get_user(
        self, username: Optional[str] = None, user_id: Optional[str] = None
    ) -> Optional[User]:
        """
        How to retrieve a single user from the current authentication db,
        based on the unique username or the user_id
        return None if no filter parameter is given
        """
        ...

    @abstractmethod
    def get_users(self) -> List[User]:
        """
        How to retrieve a list of all users from the current authentication db
        """
        ...

    @abstractmethod
    def save_user(self, user: User) -> bool:
        # log.error("Users are not saved in base authentication")
        ...

    @abstractmethod
    def delete_user(self, user: User) -> bool:
        # log.error("Users are not deleted in base authentication")
        ...

    @abstractmethod
    def get_group(
        self, group_id: Optional[str] = None, name: Optional[str] = None
    ) -> Optional[Group]:
        """
        How to retrieve a single group from the current authentication db
        """
        ...

    @abstractmethod
    def get_groups(self) -> List[Group]:
        """
        How to retrieve groups list from the current authentication db
        """
        ...

    @abstractmethod
    def get_user_group(self, user: User) -> Group:
        """
        How to retrieve the group that the user belongs to from the current auth db
        """
        ...

    @abstractmethod
    def get_group_members(self, group: Group) -> List[User]:
        """
        How to retrieve group users list from the current authentication db
        """
        ...

    @abstractmethod
    def save_group(self, group: Group) -> bool:
        ...

    @abstractmethod
    def delete_group(self, group: Group) -> bool:
        ...

    @abstractmethod
    def get_tokens(
        self,
        user: Optional[User] = None,
        token_jti: Optional[str] = None,
        get_all: bool = False,
    ) -> List[Token]:
        """
        Return the list of tokens
        """
        ...

    @abstractmethod
    def verify_token_validity(self, jti: str, user: User) -> bool:
        """
        This method MUST be implemented by specific Authentication Methods
        to add more specific validation contraints
        """
        ...

    @abstractmethod
    def save_token(
        self, user: User, token: str, payload: Payload, token_type: Optional[str] = None
    ) -> None:
        log.debug("Tokens is not saved in base authentication")

    @abstractmethod
    def invalidate_token(self, token: str) -> bool:
        """
        With this method the specified token must be invalidated
        as expected after a user logout
        """
        ...

    @abstractmethod
    def get_roles(self) -> List[RoleObj]:
        """
        How to retrieve all the roles
        """
        ...

    @abstractmethod
    def get_roles_from_user(self, user: Optional[User]) -> List[str]:
        """
        Retrieve roles from a user object from the current auth service
        """
        ...

    @abstractmethod
    def create_role(self, name: str, description: str) -> None:
        """
        A method to create a new role
        """
        ...

    @abstractmethod
    def save_role(self, role: RoleObj) -> bool:
        ...

    # ################
    # # Create Users #
    # ################
    @abstractmethod
    def create_user(self, userdata: Dict[str, Any], roles: List[str]) -> User:
        """
        A method to create a new user
        """
        ...

    @abstractmethod
    def link_roles(self, user: User, roles: List[str]) -> None:
        """
        A method to assign roles to a user
        """
        ...

    @abstractmethod
    def create_group(self, groupdata: Dict[str, Any]) -> Group:
        """
        A method to create a new group
        """
        ...

    @abstractmethod
    def add_user_to_group(self, user: User, group: Group) -> None:
        """
        Save the group.members -> user relationship
        """
        ...

    @abstractmethod
    def save_login(self, username: str, user: Optional[User], failed: bool) -> None:
        """
        Save login information
        """
        ...

    @abstractmethod
    def get_logins(
        self, username: Optional[str] = None, only_unflushed: bool = False
    ) -> List[Login]:
        """
        Save login information
        """
        ...

    @abstractmethod
    def flush_failed_logins(self, username: str) -> None:
        """
        Flush failed logins for the give username
        """
        ...


class NoAuthentication(BaseAuthentication):  # pragma: no cover

    # Also used by POST user
    def create_user(self, userdata: Dict[str, Any], roles: List[str]) -> User:
        raise NotImplementedError("Create User not implemented with No Authentication")

    def link_roles(self, user: User, roles: List[str]) -> None:
        return None

    def create_group(self, groupdata: Dict[str, Any]) -> Group:
        raise NotImplementedError("Create Group not implemented with No Authentication")

    def add_user_to_group(self, user: User, group: Group) -> None:
        return None

    def get_user(
        self, username: Optional[str] = None, user_id: Optional[str] = None
    ) -> Optional[User]:

        return None

    def get_users(self) -> List[User]:
        return []

    def save_user(self, user: User) -> bool:
        return False

    def delete_user(self, user: User) -> bool:
        return False

    def get_group(
        self, group_id: Optional[str] = None, name: Optional[str] = None
    ) -> Optional[Group]:
        return None

    def get_groups(self) -> List[Group]:
        return []

    def get_user_group(self, user: User) -> Group:
        raise NotImplementedError("Get Group not implemented with No Authentication")

    def get_group_members(self, group: Group) -> List[User]:
        return []

    def save_group(self, group: Group) -> bool:
        return False

    def delete_group(self, group: Group) -> bool:
        return False

    def get_roles(self) -> List[RoleObj]:
        return []

    def get_roles_from_user(self, user: Optional[User]) -> List[str]:
        return []

    def create_role(self, name: str, description: str) -> None:
        return None

    def save_role(self, role: RoleObj) -> bool:
        return False

    def save_token(
        self, user: User, token: str, payload: Payload, token_type: Optional[str] = None
    ) -> None:
        return None

    def verify_token_validity(self, jti: str, user: User) -> bool:
        return False

    def get_tokens(
        self,
        user: Optional[User] = None,
        token_jti: Optional[str] = None,
        get_all: bool = False,
    ) -> List[Token]:

        return []

    def invalidate_token(self, token: str) -> bool:
        return False

    def save_login(self, username: str, user: Optional[User], failed: bool) -> None:
        return None

    def get_logins(
        self, username: Optional[str] = None, only_unflushed: bool = False
    ) -> List[Login]:
        raise NotImplementedError("Get Login not implemented with No Authentication")

    def flush_failed_logins(self, username: str) -> None:
        return None
