"""
Connector based on SQLalchemy with automatic integration with RAPyDo framework
"""

import re
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, cast

import pytz
from psycopg2 import OperationalError as PsycopgOperationalError
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine.base import Connection, Engine
from sqlalchemy.engine.url import URL
from sqlalchemy.exc import (
    DatabaseError,
    IntegrityError,
    InternalError,
    InvalidRequestError,
    OperationalError,
    ProgrammingError,
    StatementError,
)

# Module "sqlalchemy.orm" has no attribute "declarative_base"
from sqlalchemy.orm import (  # type: ignore
    Session,
    declarative_base,
    scoped_session,
    sessionmaker,
)
from sqlalchemy.orm.attributes import set_attribute
from sqlalchemy.orm.session import close_all_sessions

from restapi.config import (
    BACKEND_PACKAGE,
    CUSTOM_PACKAGE,
    EXTENDED_PACKAGE,
    EXTENDED_PROJECT_DISABLED,
)
from restapi.connectors import Connector, ExceptionsList
from restapi.env import Env
from restapi.exceptions import (
    BadRequest,
    DatabaseDuplicatedEntry,
    DatabaseMissingRequiredProperty,
    RestApiException,
    ServiceUnavailable,
)
from restapi.services.authentication import (
    BaseAuthentication,
    Group,
    Login,
    Payload,
    RoleObj,
    Token,
    User,
)
from restapi.utilities.logs import Events, log
from restapi.utilities.meta import Meta
from restapi.utilities.time import get_now
from restapi.utilities.uuid import getUUID

# used as a base to define Models
db = declarative_base()

F = TypeVar("F", bound=Callable[..., Any])


def parse_postgres_duplication_error(excpt: List[str]) -> Optional[str]:
    if m0 := re.search(
        r".*duplicate key value violates unique constraint \"(.*)\"", excpt[0]
    ):
        # duplicate key value violates unique constraint "user_email_key"
        # => m0.group(1) === user_email_key
        # => table = user
        table = m0.group(1).split("_")[0]
        m = re.search(r"DETAIL:  Key \((.+)\)=\((.+)\) already exists.", excpt[1])

        if m:
            prop = m.group(1)
            val = m.group(2)
            return f"A {table.title()} already exists with {prop}: {val}"

    return None


def parse_missing_error(excpt: List[str]) -> Optional[str]:

    if m := re.search(
        r"null value in column \"(.*)\" of relation \"(.*)\" "
        "violates not-null constraint",
        excpt[0],
    ):
        prop = m.group(1)
        table = m.group(2)

        return f"Missing property {prop} required by {table.title()}"

    if m0 := re.search(r".*Column '(.*)' cannot be null.*", excpt[0]):

        prop = m0.group(1)

        # table name can be "tablename" or "`tablename`"
        # => match all non-space and non-backticks characters optioanlly wrapped among `
        m = re.search(r".*INSERT INTO `?([^\s`]+)`? \(.*", excpt[1])

        if m:
            table = m.group(1)
            return f"Missing property {prop} required by {table.title()}"

    return None  # pragma: no cover


def catch_db_exceptions(func: F) -> F:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:

        try:
            return func(*args, **kwargs)
        except RestApiException:
            # already catched and parser, raise up
            raise
        except IntegrityError as e:
            message = str(e).split("\n")

            if error := parse_postgres_duplication_error(message):
                raise DatabaseDuplicatedEntry(error)

            if error := parse_missing_error(message):
                raise DatabaseMissingRequiredProperty(error)

            # Should never happen except in case of a new alchemy version
            log.error("Unrecognized error message: {}", e)  # pragma: no cover
            raise ServiceUnavailable("Duplicated entry")  # pragma: no cover

        except InternalError as e:  # pragma: no cover

            m = re.search(
                r"Incorrect string value: '(.*)' for column `.*`.`.*`.`(.*)` at row .*",
                str(e),
            )

            if m:
                value = m.group(1)
                column = m.group(2)
                error = f"Invalid {column}: {value}"
                raise BadRequest(error)

            log.error("Unrecognized error message: {}", e)
            raise

        except ProgrammingError as e:
            # Ignore ProgrammingError (like Table doesn't exist) during initialization
            if not SQLAlchemy.DB_INITIALIZING:
                message = str(e).split("\n")
                log.error(message[0])
                if len(message) > 1:
                    log.info(message[1])

            raise

        except Exception as e:  # pragma: no cover
            log.critical("Raised unknown exception {}: {}", e.__class__.__name__, e)
            raise

    return cast(F, wrapper)


class SQLAlchemy(Connector):
    # Used to suppress some errors raised during DB initialization
    DB_INITIALIZING = False

    def __init__(self) -> None:
        # Type of variable becomes "Any" due to an unfollowed import
        self.db: Any = None
        self.engine_bis: Optional[Engine] = None
        super().__init__()

    def __getattr__(self, name: str) -> Any:
        if name in self._models:
            return self._models[name]
        raise AttributeError(f"Model {name} not found")

    @staticmethod
    def is_mysql() -> bool:
        # could be based on self.variables but this version Env based
        # can be used as static method and be used before creating instances
        return (
            Env.get("AUTH_SERVICE", "NO_AUTHENTICATION") == "sqlalchemy"
            and Env.get("ALCHEMY_DBTYPE", "postgresql") == "mysql+pymysql"
        )

    @staticmethod
    def get_connection_exception() -> ExceptionsList:
        # type is ignored here due to untyped psycopg2
        return (
            OperationalError,
            PsycopgOperationalError,
        )  # type: ignore

    def connect(self, **kwargs: str) -> "SQLAlchemy":

        variables = self.variables.copy()
        variables.update(kwargs)

        query = None
        if self.is_mysql() and not Connector.is_external(variables.get("host", "")):
            query = {"charset": "utf8mb4"}

        uri = URL.create(  # type: ignore
            drivername=variables.get("dbtype", "postgresql"),
            username=variables.get("user"),
            password=variables.get("password"),
            host=variables.get("host"),
            port=variables.get("port"),
            database=variables.get("db"),
            query=query,
        )

        self.engine_bis = create_engine(uri, encoding="utf8")
        db.session = scoped_session(sessionmaker(bind=self.engine_bis))
        db.session.commit = catch_db_exceptions(db.session.commit)  # type: ignore
        db.session.flush = catch_db_exceptions(db.session.flush)  # type: ignore
        # db.update_properties = self.update_properties
        # db.disconnect = self.disconnect
        # db.is_connected = self.is_connected

        Connection.execute = catch_db_exceptions(Connection.execute)  # type: ignore
        # Used in case of autoflush
        Connection._execute_context = catch_db_exceptions(Connection._execute_context)  # type: ignore

        sql = text("SELECT 1")
        db.session.execute(sql)

        self.load_models()
        self.db = db
        return self

    @property
    def session(self) -> Session:
        return cast(Session, self.db.session)

    def disconnect(self) -> None:
        if self.db:
            self.db.session.close()
        self.disconnected = True

    def is_connected(self) -> bool:
        log.warning("sqlalchemy.is_connected method is not implemented")
        return not self.disconnected

    def initialize(self) -> None:
        instance = self.get_instance()
        sql = text("SELECT 1")
        instance.db.session.execute(sql)

        SQLAlchemy.DB_INITIALIZING = True
        instance.db.metadata.create_all(self.engine_bis)
        SQLAlchemy.DB_INITIALIZING = False

    def destroy(self) -> None:
        instance = self.get_instance()
        sql = text("SELECT 1")
        instance.db.session.execute(sql)

        instance.db.session.remove()
        close_all_sessions()
        # massive destruction
        log.critical("Destroy current SQL data")
        instance.db.metadata.drop_all(self.engine_bis)

    @staticmethod
    def update_properties(instance: Any, properties: Dict[str, Any]) -> None:

        for field, value in properties.items():
            set_attribute(instance, field, value)  # type: ignore


class Authentication(BaseAuthentication):
    def __init__(self) -> None:
        self.db: SQLAlchemy = get_instance()

    def init_auth_db(self, options: Dict[str, bool]) -> None:
        self.db.initialize()
        return super().init_auth_db(options)

    # Also used by POST user
    def create_user(self, userdata: Dict[str, Any], roles: List[str]) -> User:

        userdata.setdefault("authmethod", "credentials")
        userdata.setdefault("uuid", getUUID())

        if "password" in userdata:
            userdata["password"] = self.get_password_hash(userdata["password"])

        userdata, extra_userdata = self.custom_user_properties_pre(userdata)

        user = self.db.User(**userdata)
        self.link_roles(user, roles)

        self.custom_user_properties_post(user, userdata, extra_userdata, self.db)

        self.db.session.add(user)

        return user

    def link_roles(self, user: User, roles: List[str]) -> None:

        if not roles:
            roles = [BaseAuthentication.default_role]

        # link roles into users
        user.roles = []
        for role in roles:
            sqlrole = self.db.session.execute(
                select(self.db.Role).where(self.db.Role.name == role)
            ).scalar()

            user.roles.append(sqlrole)

    def create_group(self, groupdata: Dict[str, Any]) -> Group:

        groupdata.setdefault("uuid", getUUID())

        group = self.db.Group(**groupdata)

        self.db.session.add(group)
        self.db.session.commit()

        return group

    def add_user_to_group(self, user: User, group: Group) -> None:

        if user and group:
            user.belongs_to = group

            self.db.session.add(user)
            self.db.session.commit()

    def get_user(
        self, username: Optional[str] = None, user_id: Optional[str] = None
    ) -> Optional[User]:
        try:

            if username:
                return self.db.session.execute(
                    select(self.db.User).where(self.db.User.email == username)
                ).scalar()

            if user_id:
                return self.db.session.execute(
                    select(self.db.User).where(self.db.User.uuid == user_id)
                ).scalar()

        except (StatementError, InvalidRequestError) as e:
            log.error(e)
            raise ServiceUnavailable("Backend database is unavailable")
        except (
            DatabaseError,
            OperationalError,
        ) as e:  # pragma: no cover
            raise e

        # only reached if both username and user_id are None
        return None

    def get_users(self) -> List[User]:
        return list(self.db.session.execute(select(self.db.User)).scalars())

    def save_user(self, user: User) -> bool:
        if not user:
            return False

        self.db.session.add(user)
        self.db.session.commit()
        return True

    def delete_user(self, user: User) -> bool:
        if not user:
            return False

        # Call to untyped function "delete" in typed context
        self.db.session.delete(user)  # type: ignore
        self.db.session.commit()
        return True

    def get_group(
        self, group_id: Optional[str] = None, name: Optional[str] = None
    ) -> Optional[Group]:
        if group_id:
            return self.db.session.execute(
                select(self.db.Group).where(self.db.Group.uuid == group_id)
            ).scalar()

        if name:
            return self.db.session.execute(
                select(self.db.Group).where(self.db.Group.shortname == name)
            ).scalar()

        return None

    def get_groups(self) -> List[Group]:
        return list(self.db.session.execute(select(self.db.Group)).scalars())

    def get_user_group(self, user: User) -> Group:
        return user.belongs_to

    def get_group_members(self, group: Group) -> List[User]:
        return list(group.members)

    def save_group(self, group: Group) -> bool:
        if not group:
            return False

        self.db.session.add(group)
        self.db.session.commit()
        return True

    def delete_group(self, group: Group) -> bool:
        if not group:
            return False

        # Call to untyped function "delete" in typed context
        self.db.session.delete(group)  # type: ignore
        self.db.session.commit()
        return True

    def get_roles(self) -> List[RoleObj]:
        if not inspect(self.db.engine_bis).has_table("role"):
            return []
        return list(self.db.session.execute(select(self.db.Role)).scalars())

    def get_roles_from_user(self, user: Optional[User]) -> List[str]:
        # No user for non authenticated endpoints -> return no role
        if user is None:
            return []

        return [role.name for role in user.roles]

    def create_role(self, name: str, description: str) -> None:
        role = self.db.Role(name=name, description=description)
        self.db.session.add(role)
        self.db.session.commit()

    def save_role(self, role: RoleObj) -> bool:
        if role:
            self.db.session.add(role)
            self.db.session.commit()
            return True
        return False

    def save_token(
        self, user: User, token: str, payload: Payload, token_type: Optional[str] = None
    ) -> None:

        ip_address = self.get_remote_ip()

        if token_type is None:
            token_type = self.FULL_TOKEN

        now = datetime.now(pytz.utc)
        exp = payload.get("exp", now + timedelta(seconds=self.DEFAULT_TOKEN_TTL))

        token_entry = self.db.Token(
            jti=payload["jti"],
            token=token,
            token_type=token_type,
            creation=now,
            last_access=now,
            expiration=exp,
            IP=ip_address,
            location="Unknown",
            emitted_for=user,
        )

        try:
            self.db.session.add(token_entry)
            # Save user updated in profile endpoint
            self.db.session.add(user)
            self.db.session.commit()

        except Exception as e:  # pragma: no cover
            log.error("DB error ({}), rolling back", e)
            self.db.session.rollback()

    def verify_token_validity(self, jti: str, user: User) -> bool:
        token_entry = self.db.session.execute(
            select(self.db.Token).where(self.db.Token.jti == jti)
        ).scalar()

        if token_entry is None:
            return False
        if token_entry.user_id is None or token_entry.user_id != user.id:
            return False

        now = get_now(token_entry.expiration.tzinfo)

        if now > token_entry.expiration:
            self.invalidate_token(token=token_entry.token)
            log.info(
                "This token is no longer valid: expired since {}",
                token_entry.expiration.strftime("%d/%m/%Y"),
            )
            return False

        # Verify IP validity only after grace period is expired
        if token_entry.creation + self.GRACE_PERIOD < now:
            ip = self.get_remote_ip()
            if token_entry.IP != ip:
                log.warning(
                    "This token is emitted for IP {}, invalid use from {}",
                    token_entry.IP,
                    ip,
                )
                return False

        if token_entry.last_access + self.SAVE_LAST_ACCESS_EVERY < now:
            token_entry.last_access = now

            try:
                self.db.session.add(token_entry)
                self.db.session.commit()
            except Exception as e:  # pragma: no cover
                log.error("DB error ({}), rolling back", e)
                self.db.session.rollback()

        return True

    def get_tokens(
        self,
        user: Optional[User] = None,
        token_jti: Optional[str] = None,
        get_all: bool = False,
    ) -> List[Token]:

        tokens_list: List[Token] = []
        tokens = None

        if get_all:
            tokens = self.db.session.execute(select(self.db.Token)).scalars()

        elif user:
            tokens = user.tokens
        elif token_jti:
            tokens = self.db.session.execute(
                select(self.db.Token).where(self.db.Token.jti == token_jti)
            ).scalars()

        if tokens:
            for token in tokens:

                if token is None:
                    continue

                t: Token = {
                    "id": token.jti,
                    "token": token.token,
                    "token_type": token.token_type,
                    "emitted": token.creation,
                    "last_access": token.last_access,
                    "expiration": token.expiration,
                    "IP": token.IP,
                    "location": token.location,
                }
                if get_all:
                    t["user"] = token.emitted_for
                tokens_list.append(t)

        return tokens_list

    def invalidate_token(self, token: str) -> bool:
        token_entry = self.db.session.execute(
            select(self.db.Token).where(self.db.Token.token == token)
        ).scalar()
        if token_entry:
            try:
                # Call to untyped function "delete" in typed context
                self.db.session.delete(token_entry)  # type: ignore
                self.db.session.commit()
                self.log_event(Events.delete, target=token_entry)
                return True
            except Exception as e:  # pragma: no cover
                log.error("Could not invalidate token ({}), rolling back", e)
                self.db.session.rollback()
                return False

        log.warning("Could not invalidate token")
        return False

    def save_login(self, username: str, user: Optional[User], failed: bool) -> None:

        date = datetime.now(pytz.utc)
        ip_address = self.get_remote_ip()

        login_data: Dict[str, Any] = {}

        login_data["date"] = date
        login_data["username"] = username
        login_data["IP"] = ip_address
        login_data["location"] = "Unknown"
        if user:
            login_data["user"] = user
        login_data["failed"] = failed
        # i.e. failed logins are not flushed by default
        # success logins are automatically flushed
        login_data["flushed"] = not failed

        login = self.db.Login(**login_data)

        try:
            self.db.session.add(login)
            self.db.session.commit()

        except Exception as e:  # pragma: no cover
            log.error("DB error ({}), rolling back", e)
            self.db.session.rollback()
            raise

    def get_logins(
        self, username: Optional[str] = None, only_unflushed: bool = False
    ) -> List[Login]:
        logins = select(self.db.Login)
        if username:
            logins = logins.where(self.db.Login.username == username)
            if only_unflushed:
                logins = logins.where(self.db.Login.flushed == False)  # noqa
        return list(self.db.session.execute(logins).scalars())

    def flush_failed_logins(self, username: str) -> None:
        for login in self.db.session.execute(
            select(self.db.Login)
            .where(self.db.Login.username == username)
            .where(
                self.db.Login.flushed == False,  # noqa
            )
        ).scalars():
            login.flushed = True
            self.db.session.add(login)

        self.db.session.commit()


instance = SQLAlchemy()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    retries: int = 1,
    retry_wait: int = 0,
    **kwargs: str,
) -> "SQLAlchemy":

    return instance.get_instance(
        verification=verification,
        expiration=expiration,
        retries=retries,
        retry_wait=retry_wait,
        **kwargs,
    )
