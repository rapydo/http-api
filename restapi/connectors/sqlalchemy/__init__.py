""" Wrapper for the existing Flask-SQLalchemy

NOTE: Flask Sqlalchemy needs to have models defined on existing instance;
for this reason we create the sql instance where models are defined.

For future lazy alchemy: http://flask.pocoo.org/snippets/22/
"""

import re
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, cast

import pytz
import sqlalchemy
from flask_migrate import Migrate
from flask_sqlalchemy import Model
from flask_sqlalchemy import SQLAlchemy as OriginalAlchemy
from psycopg2 import OperationalError as PsycopgOperationalError
from sqlalchemy import create_engine, text
from sqlalchemy.engine.base import Connection
from sqlalchemy.engine.url import URL
from sqlalchemy.exc import (
    IntegrityError,
    InternalError,
    OperationalError,
    ProgrammingError,
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
from restapi.utilities.logs import Events, log
from restapi.utilities.time import get_now
from restapi.utilities.uuid import getUUID

# all instances have to use the same alchemy object
db = OriginalAlchemy()

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


def parse_mysql_duplication_error(excpt: List[str]) -> Optional[str]:

    if m0 := re.search(r".*Duplicate entry '(.*)' for key '(.*)'.*", excpt[0]):

        val = m0.group(1)
        prop = m0.group(2)

        # table name can be "tablename" or "`tablename`"
        # => match all non-space and non-backticks characters optioanlly wrapped among `
        m = re.search(r".*INSERT INTO `?([^\s`]+)`? \(.*", excpt[1])

        if m:
            table = m.group(1)
            return f"A {table.title()} already exists with {prop}: {val}"

    return None  # pragma: no cover


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

            if error := parse_mysql_duplication_error(message):
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
    # Used to suppress ProgrammingError raised by MySQL during DB initialization
    DB_INITIALIZING = False

    def __init__(self) -> None:
        # Type of variable becomes "Any" due to an unfollowed import
        self.db: OriginalAlchemy = None  # type: ignore
        super().__init__()

    # This is used to return Models in a type-safe way
    # Return type becomes "Any" due to an unfollowed import
    def __getattr__(self, name: str) -> Model:  # type: ignore
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
        # return self.variables.get("dbtype", "postgresql") == "mysql+pymysql"

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
        # TODO: in case we need different connection binds
        # (multiple connections with sql) then:
        # SQLALCHEMY_BINDS = {
        #     'users':        'mysqldb://localhost/users',
        #     'appmeta':      'sqlite:////path/to/appmeta.db'
        # }
        if self.app:
            self.app.config["SQLALCHEMY_DATABASE_URI"] = uri
            # self.app.config['SQLALCHEMY_POOL_TIMEOUT'] = 3
            self.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

            # The Alembic package, which handles the migration work, does not recognize
            # type changes in columns by default. If you want that fine level of
            # detection you need to enable the compare_type option
            Migrate(self.app, db, compare_type=True)

        # Overwrite db.session created by flask_alchemy due to errors
        # with transaction when concurrent requests...

        db.engine_bis = create_engine(uri, encoding="utf8")
        db.session = scoped_session(sessionmaker(bind=db.engine_bis))
        db.session.commit = catch_db_exceptions(db.session.commit)  # type: ignore
        db.session.flush = catch_db_exceptions(db.session.flush)  # type: ignore
        # db.update_properties = self.update_properties
        # db.disconnect = self.disconnect
        # db.is_connected = self.is_connected

        Connection.execute = catch_db_exceptions(Connection.execute)  # type: ignore
        # Used in case of autoflush
        Connection._execute_context = catch_db_exceptions(Connection._execute_context)  # type: ignore

        if self.app:
            # This is to prevent multiple app initialization and avoid the error:
            #   A setup function was called after the first request was handled.
            #   This usually indicates a bug in the application where a module was
            #   not imported and decorators or other functionality was called too late.
            #   To fix this make sure to import all your view modules,
            #   database models and everything related at a central place before
            #   the application starts serving requests.
            if "sqlalchemy" not in self.app.extensions:
                db.init_app(self.app)

            # This is needed to test the connection
            with self.app.app_context():
                sql = text("SELECT 1")
                db.engine.execute(sql)
        # This is to test the connection when executed from the cli (i.e. outside flask)

        else:
            sql = text("SELECT 1")
            db.session.execute(sql)

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

        if self.app:
            with self.app.app_context():

                sql = text("SELECT 1")
                instance.db.engine.execute(sql)

                SQLAlchemy.DB_INITIALIZING = True
                instance.db.create_all()
                SQLAlchemy.DB_INITIALIZING = False

    def destroy(self) -> None:

        instance = self.get_instance()

        if self.app:
            with self.app.app_context():

                sql = text("SELECT 1")
                instance.db.engine.execute(sql)

                instance.db.session.remove()
                # Deprecated since v1.3
                # instance.db.session.close_all()
                close_all_sessions()
                # massive destruction
                log.critical("Destroy current SQL data")
                instance.db.drop_all()

    @staticmethod
    # Argument 1 to "update_properties" becomes "Any" due to an unfollowed import
    def update_properties(instance: Model, properties: Dict[str, Any]) -> None:  # type: ignore

        for field, value in properties.items():
            # Call to untyped function "set_attribute" in typed context
            set_attribute(instance, field, value)  # type: ignore


class Authentication(BaseAuthentication):
    def __init__(self) -> None:
        self.db: SQLAlchemy = get_instance()

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
            sqlrole = self.db.Role.query.filter_by(name=role).first()
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
                return self.db.User.query.filter_by(email=username).first()

            if user_id:
                return self.db.User.query.filter_by(uuid=user_id).first()

        except (sqlalchemy.exc.StatementError, sqlalchemy.exc.InvalidRequestError) as e:
            log.error(e)
            raise ServiceUnavailable("Backend database is unavailable")
        except (
            sqlalchemy.exc.DatabaseError,
            sqlalchemy.exc.OperationalError,
        ) as e:  # pragma: no cover
            raise e

        # only reached if both username and user_id are None
        return None

    def get_users(self) -> List[User]:
        return cast(List[User], self.db.User.query.all())

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
            return self.db.Group.query.filter_by(uuid=group_id).first()

        if name:
            return self.db.Group.query.filter_by(shortname=name).first()

        return None

    def get_groups(self) -> List[Group]:
        return cast(List[Group], self.db.Group.query.all())

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
        roles = []
        for role in self.db.Role.query.all():
            if role:
                roles.append(role)

        return roles

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
        ip_loc = self.localize_ip(ip_address)

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
            location=ip_loc or "Unknown",
            # the following two are equivalent
            # user_id=user.id,
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

        token_entry = self.db.Token.query.filter_by(jti=jti).first()

        if token_entry is None:
            return False
        if token_entry.user_id is None or token_entry.user_id != user.id:
            return False

        # offset-naive datetime to compare with MySQL
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
            tokens = self.db.Token.query.all()
        elif user:
            tokens = user.tokens.all()
        elif token_jti:
            tokens = [self.db.Token.query.filter_by(jti=token_jti).first()]

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

        token_entry = self.db.Token.query.filter_by(token=token).first()
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
        ip_location = self.localize_ip(ip_address)

        login_data: Dict[str, Any] = {}

        login_data["date"] = date
        login_data["username"] = username
        login_data["IP"] = ip_address
        login_data["location"] = ip_location or "Unknown"
        # the following two are equivalent
        if user:
            # login_data["user_id"] = user.id
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

        if not username:
            logins = self.db.Login.query.all()
        elif only_unflushed:
            logins = self.db.Login.query.filter_by(username=username, flushed=False)
        else:
            logins = self.db.Login.query.filter_by(username=username)

        return [x for x in logins]

    def flush_failed_logins(self, username: str) -> None:

        for login in self.db.Login.query.filter_by(username=username, flushed=False):
            login.flushed = True
            self.db.session.add(login)

        self.db.session.commit()


instance = SQLAlchemy()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: str,
) -> "SQLAlchemy":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
