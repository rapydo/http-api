"""
Connector based on SQLalchemy with automatic integration with RAPyDo framework
"""

import re
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, cast

import pytz
from psycopg2 import OperationalError as PsycopgOperationalError
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine.base import Connection
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
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from sqlalchemy.orm.attributes import set_attribute
from sqlalchemy.orm.session import close_all_sessions

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
from restapi.utilities.globals import mem
from restapi.utilities.logs import Events, log
from restapi.utilities.uuid import getUUID

F = TypeVar("F", bound=Callable[..., Any])


def parse_postgres_duplication_error(excpt: list[str]) -> Optional[str]:
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


def parse_missing_error(excpt: list[str]) -> Optional[str]:
    if m := re.search(
        r"null value in column \"(.*)\" of relation \"(.*)\" "
        "violates not-null constraint",
        excpt[0],
    ):
        prop = m.group(1)
        table = m.group(2)

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
                raise DatabaseDuplicatedEntry(error) from e

            if error := parse_missing_error(message):
                raise DatabaseMissingRequiredProperty(error) from e

            # Should never happen except in case of a new alchemy version
            log.error("Unrecognized error message: {}", e)  # pragma: no cover
            raise ServiceUnavailable("Duplicated entry") from e  # pragma: no cover

        except InternalError as e:  # pragma: no cover
            m = re.search(
                r"Incorrect string value: '(.*)' for column `.*`.`.*`.`(.*)` at row .*",
                str(e),
            )

            if m:
                value = m.group(1)
                column = m.group(2)
                error = f"Invalid {column}: {value}"
                raise BadRequest(error) from e

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
    _session: Optional[scoped_session[Session]] = None

    def __init__(self) -> None:
        # Type of variable becomes "Any" due to an unfollowed import
        self.db: Any = None
        # self.engine: Optional[Engine] = None
        super().__init__()

    def __getattr__(self, name: str) -> Any:
        if name in self._models:
            return self._models[name]
        raise AttributeError(f"Model {name} not found")

    @staticmethod
    def get_connection_exception() -> ExceptionsList:
        return (
            OperationalError,
            PsycopgOperationalError,
        )  # type: ignore[return-value]

    def connect(self, **kwargs: str) -> "SQLAlchemy":
        variables = self.variables | kwargs

        uri = URL.create(
            drivername=variables.get("dbtype", "postgresql"),
            username=variables.get("user"),
            password=variables.get("password"),
            host=variables.get("host"),
            port=Env.to_int(variables.get("port"), 5432),
            database=variables.get("db"),
            query={},
        )

        poolsize = Env.to_int(variables.get("poolsize"), 30)
        if uri not in mem.sqlalchemy_engines:
            mem.sqlalchemy_engines[uri] = create_engine(
                uri,
                pool_size=poolsize,
                max_overflow=poolsize + 10,
                execution_options={"isolation_level": "READ COMMITTED"},
                future=True,
            )
        engine = mem.sqlalchemy_engines[uri]
        if len(mem.sqlalchemy_engines) == 1:
            # None URL is used as default URL
            mem.sqlalchemy_engines[None] = mem.sqlalchemy_engines[uri]

        # avoid circular imports
        from restapi.connectors.sqlalchemy.models import Base as db

        self._session = scoped_session(sessionmaker(bind=engine))
        self._session.commit = catch_db_exceptions(self._session.commit)  # type: ignore
        self._session.flush = catch_db_exceptions(self._session.flush)  # type: ignore
        Connection.execute = catch_db_exceptions(Connection.execute)  # type: ignore
        # Used in case of autoflush - shouldn't be needed with sqlalchemy 2?
        Connection._execute_context = catch_db_exceptions(Connection._execute_context)  # type: ignore  # noqa

        sql = text("SELECT 1")
        self.session.execute(sql)

        self.load_models()
        self.db = db
        return self

    @property
    def session(self) -> scoped_session[Session]:
        if self._session is None:  # pragma: no cover
            raise ServiceUnavailable("Session not initialized")
        return self._session

    def disconnect(self) -> None:
        if self._session:
            self._session.remove()
        self.disconnected = True

    def is_connected(self) -> bool:
        log.warning("sqlalchemy.is_connected method is not implemented")
        return not self.disconnected

    def initialize(self) -> None:
        instance = self.get_instance()
        sql = text("SELECT 1")
        instance.session.execute(sql)

        SQLAlchemy.DB_INITIALIZING = True

        # Get default URL
        engine = mem.sqlalchemy_engines.get(None)
        if not engine:
            return None
        instance.db.metadata.create_all(engine)
        SQLAlchemy.DB_INITIALIZING = False

    def destroy(self) -> None:
        instance = self.get_instance()
        sql = text("SELECT 1")
        instance.session.execute(sql)

        # instance.session.remove()
        close_all_sessions()
        # Get default URL
        engine = mem.sqlalchemy_engines.get(None)
        if not engine:
            return None

        # Massive destruction
        log.critical("Destroy current SQL data")
        instance.db.metadata.drop_all(engine)

    @staticmethod
    def update_properties(instance: Any, properties: dict[str, Any]) -> None:
        for field, value in properties.items():
            set_attribute(instance, field, value)


class Authentication(BaseAuthentication):
    def __init__(self) -> None:
        self.db: SQLAlchemy = get_instance()

    def init_auth_db(self, options: dict[str, bool]) -> None:
        self.db.initialize()
        return super().init_auth_db(options)

    # Also used by POST user
    def create_user(
        self, userdata: dict[str, Any], roles: list[str], group: Group
    ) -> User:
        userdata.setdefault("authmethod", "credentials")
        userdata.setdefault("uuid", getUUID())

        if "password" in userdata:
            userdata["password"] = self.get_password_hash(userdata["password"])

        userdata["group_id"] = group.id
        userdata, extra_userdata = self.custom_user_properties_pre(userdata)

        user = self.db.User(**userdata)
        self.link_roles(user, roles)

        self.custom_user_properties_post(user, userdata, extra_userdata, self.db)

        self.db.session.add(user)
        # why commit is not needed here!?
        return user

    def link_roles(self, user: User, roles: list[str]) -> None:
        if not roles:
            roles = [BaseAuthentication.default_role]

        roles_instances = []
        for role in roles:
            sqlrole = self.db.session.execute(
                select(self.db.Role).where(self.db.Role.name == role)
            ).scalar()

            roles_instances.append(sqlrole)

        user.roles = roles_instances
        # why commit is not needed here!?

    def create_group(self, groupdata: dict[str, Any]) -> Group:
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
                users = self.db.session.execute(
                    select(self.db.User).where(self.db.User.email == username)
                ).scalar()
                # self.db.session.commit()
                return users

            if user_id:
                users = self.db.session.execute(
                    select(self.db.User).where(self.db.User.uuid == user_id)
                ).scalar()
                # self.db.session.commit()
                return users

        except (StatementError, InvalidRequestError) as e:
            log.error(e)
            raise ServiceUnavailable("Backend database is unavailable") from e
        except (
            DatabaseError,
            OperationalError,
        ) as e:  # pragma: no cover
            raise e

        # only reached if both username and user_id are None
        return None

    def get_users(self) -> list[User]:
        users = list(self.db.session.execute(select(self.db.User)).scalars())
        # self.db.session.commit()
        return users

    def save_user(self, user: User) -> bool:
        if not user:
            return False

        self.db.session.add(user)
        self.db.session.commit()
        return True

    def delete_user(self, user: User) -> bool:
        if not user:
            return False

        self.db.session.delete(user)
        self.db.session.commit()
        return True

    def get_group(
        self, group_id: Optional[str] = None, name: Optional[str] = None
    ) -> Optional[Group]:
        if group_id:
            group = self.db.session.execute(
                select(self.db.Group).where(self.db.Group.uuid == group_id)
            ).scalar()
            # self.db.session.commit()
            return group

        if name:
            group = self.db.session.execute(
                select(self.db.Group).where(self.db.Group.shortname == name)
            ).scalar()
            # self.db.session.commit()
            return group

        return None

    def get_groups(self) -> list[Group]:
        groups = list(self.db.session.execute(select(self.db.Group)).scalars())
        # self.db.session.commit()
        return groups

    def get_user_group(self, user: User) -> Group:
        group = user.belongs_to
        # self.db.session.commit()
        return group

    def get_group_members(self, group: Group) -> list[User]:
        members = list(group.members)
        # self.db.session.commit()
        return members

    def save_group(self, group: Group) -> bool:
        if not group:
            return False

        self.db.session.add(group)
        self.db.session.commit()
        return True

    def delete_group(self, group: Group) -> bool:
        if not group:
            return False

        self.db.session.delete(group)
        self.db.session.commit()
        return True

    def get_roles(self) -> list[RoleObj]:
        # Get default URL
        engine = mem.sqlalchemy_engines.get(None)
        if not engine and mem.sqlalchemy_engines:
            engine = list(mem.sqlalchemy_engines.values())[0]
        if not engine:
            return []

        inspect_engine = inspect(engine)
        if not inspect_engine or not inspect_engine.has_table(
            "role"
        ):  # pragma: no cover
            return []
        roles = list(self.db.session.execute(select(self.db.Role)).scalars())
        # self.db.session.commit()
        return roles

    def get_roles_from_user(self, user: Optional[User]) -> list[str]:
        # No user for non authenticated endpoints -> return no role
        if user is None:
            return []

        roles = [role.name for role in user.roles]
        # self.db.session.commit()
        return roles

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
        # self.db.session.commit()

        if token_entry is None:
            return False
        if token_entry.user_id is None or token_entry.user_id != user.id:
            return False

        now = datetime.now(pytz.utc)

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
    ) -> list[Token]:
        tokens_list: list[Token] = []
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
                if token is None:  # pragma: no cover
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

        # self.db.session.commit()
        return tokens_list

    def invalidate_token(self, token: str) -> bool:
        token_entry = self.db.session.execute(
            select(self.db.Token).where(self.db.Token.token == token)
        ).scalar()
        # self.db.session.commit()
        if token_entry:
            try:
                self.db.session.delete(token_entry)
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

        login_data: dict[str, Any] = {}

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
    ) -> list[Login]:
        logins = select(self.db.Login)
        if username:
            logins = logins.where(self.db.Login.username == username)
            if only_unflushed:
                logins = logins.where(self.db.Login.flushed == False)  # noqa
        logins_list = list(self.db.session.execute(logins).scalars())
        # self.db.session.commit()
        return logins_list

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
