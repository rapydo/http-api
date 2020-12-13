""" Wrapper for the existing Flask-SQLalchemy

NOTE: Flask Sqlalchemy needs to have models defined on existing instance;
for this reason we create the sql instance where models are defined.

For future lazy alchemy: http://flask.pocoo.org/snippets/22/
"""

import re
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Union

import pytz
import sqlalchemy
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy as OriginalAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine.base import Connection
from sqlalchemy.engine.url import URL
from sqlalchemy.exc import (
    IntegrityError,
    InternalError,
    OperationalError,
    ProgrammingError,
)
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.orm.attributes import set_attribute

# from restapi.config import TESTING
from restapi.connectors import Connector
from restapi.exceptions import BadRequest, DatabaseDuplicatedEntry, ServiceUnavailable
from restapi.services.authentication import NULL_IP, BaseAuthentication
from restapi.utilities.logs import log
from restapi.utilities.time import get_now
from restapi.utilities.uuid import getUUID

# all instances have to use the same alchemy object
db = OriginalAlchemy()


def parse_postgres_error(excpt):

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


def parse_mysql_error(excpt):

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


def catch_db_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        try:
            return func(*args, **kwargs)
        except (DatabaseDuplicatedEntry, BadRequest):
            # already catched and parser, raise up
            raise
        except IntegrityError as e:
            message = str(e).split("\n")

            error = parse_postgres_error(message)
            if not error:
                error = parse_mysql_error(message)

            # Should never happen except in case of new alchemy version
            if not error:  # pragma: no cover
                log.error("Unrecognized error message: {}", e)
                raise DatabaseDuplicatedEntry("Duplicated entry")

            raise DatabaseDuplicatedEntry(error)

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

        except BaseException as e:
            log.critical("Raised unknown exception {}: {}", e.__class__.__name__, e)
            raise

    return wrapper


class SQLAlchemy(Connector):
    # Used to suppress ProgrammingError raised by MySQL during DB initialization
    DB_INITIALIZING = False

    def __init__(self, app=None):
        self.db: OriginalAlchemy = None
        super().__init__(app)

    def is_mysql(self) -> bool:
        return self.variables.get("dbtype", "postgresql") == "mysql+pymysql"

    def get_connection_exception(self):
        return (OperationalError,)

    def connect(self, **kwargs):

        variables = self.variables.copy()
        variables.update(kwargs)

        query = None
        if self.is_mysql() and not Connector.is_external(variables.get("host", "")):
            query = {"charset": "utf8mb4"}

        uri = URL(
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
        db.session.commit = catch_db_exceptions(db.session.commit)
        db.session.flush = catch_db_exceptions(db.session.flush)
        # db.update_properties = self.update_properties
        # db.disconnect = self.disconnect
        # db.is_connected = self.is_connected

        Connection.execute = catch_db_exceptions(Connection.execute)

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

        self.db = db
        return self

    @property
    def session(self):
        return self.db.session

    def disconnect(self) -> None:
        if self.db:
            self.db.session.close()
        self.disconnected = True

    def is_connected(self):
        log.warning("sqlalchemy.is_connected method is not implemented")
        return not self.disconnected

    def initialize(self):

        instance = self.get_instance()

        if self.app:
            with self.app.app_context():

                sql = text("SELECT 1")
                instance.db.engine.execute(sql)

                SQLAlchemy.DB_INITIALIZING = True
                instance.db.create_all()
                SQLAlchemy.DB_INITIALIZING = False

    def destroy(self):

        instance = self.get_instance()

        if self.app:
            with self.app.app_context():

                sql = text("SELECT 1")
                instance.db.engine.execute(sql)

                instance.db.session.remove()
                instance.db.session.close_all()
                # massive destruction
                log.critical("Destroy current SQL data")
                instance.db.drop_all()

    @staticmethod
    def update_properties(instance, properties):

        for field, value in properties.items():
            set_attribute(instance, field, value)


class Authentication(BaseAuthentication):
    def __init__(self):
        self.db = get_instance()

    # Also used by POST user
    def create_user(self, userdata, roles):

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

    def link_roles(self, user, roles):

        if not roles:
            roles = [BaseAuthentication.default_role]

        # link roles into users
        user.roles = []
        for role in roles:
            sqlrole = self.db.Role.query.filter_by(name=role).first()
            user.roles.append(sqlrole)

    def create_group(self, groupdata):

        groupdata.setdefault("uuid", getUUID())

        group = self.db.Group(**groupdata)

        self.db.session.add(group)
        self.db.session.commit()

        return group

    def add_user_to_group(self, user, group):

        if user and group:
            user.belongs_to = group

            self.db.session.add(user)
            self.db.session.commit()

    def get_user(self, username=None, user_id=None):

        try:
            if username:
                return self.db.User.query.filter_by(email=username).first()

            if user_id:
                return self.db.User.query.filter_by(uuid=user_id).first()

        except (sqlalchemy.exc.StatementError, sqlalchemy.exc.InvalidRequestError) as e:
            log.error(e)
            raise ServiceUnavailable("Backend database is unavailable")
        except (sqlalchemy.exc.DatabaseError, sqlalchemy.exc.OperationalError) as e:
            raise e

        # only reached if both username and user_id are None
        return None

    def get_users(self):
        return self.db.User.query.all()

    def save_user(self, user):
        if user:
            self.db.session.add(user)
            self.db.session.commit()
            return True
        return False

    def delete_user(self, user):
        if user:
            self.db.session.delete(user)
            self.db.session.commit()
            return True
        return False

    def get_group(self, group_id=None, name=None):
        if group_id:
            return self.db.Group.query.filter_by(uuid=group_id).first()

        if name:
            return self.db.Group.query.filter_by(shortname=name).first()

        return None

    def get_groups(self):
        return self.db.Group.query.all()

    def save_group(self, group):
        if group:
            self.db.session.add(group)
            self.db.session.commit()
            return True
        return False

    def delete_group(self, group):
        if group:
            self.db.session.delete(group)
            self.db.session.commit()
            return True
        return False

    def get_roles(self):
        roles = []
        for role_name in self.roles:
            role = self.db.Role.query.filter_by(name=role_name).first()
            if role:
                roles.append(role)

        return roles

    def get_roles_from_user(self, userobj):

        # No user for on authenticated endpoints -> return no role
        if userobj is None:
            return []

        return [role.name for role in userobj.roles]

    def create_role(self, name, description):
        role = self.db.Role(name=name, description=description)
        self.db.session.add(role)
        self.db.session.commit()

    def save_role(self, role):
        if role:
            self.db.session.add(role)
            self.db.session.commit()
            return True
        return False

    def save_token(self, user, token, payload, token_type=None):

        ip = self.get_remote_ip()
        ip_loc = self.localize_ip(ip)

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
            IP=ip or NULL_IP,
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

        except BaseException as e:
            log.error("DB error ({}), rolling back", e)
            self.db.session.rollback()

    def verify_token_validity(self, jti, user):

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
        if token_entry.last_access + self.GRACE_PERIOD < now:
            ip = self.get_remote_ip()
            if token_entry.IP != ip:
                log.error(
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
            except BaseException as e:
                log.error("DB error ({}), rolling back", e)
                self.db.session.rollback()

        return True

    def get_tokens(self, user=None, token_jti=None, get_all=False):

        tokens_list = []
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

                t = {}

                t["id"] = token.jti
                t["token"] = token.token
                t["token_type"] = token.token_type
                t["emitted"] = token.creation
                t["last_access"] = token.last_access
                t["expiration"] = token.expiration
                t["IP"] = token.IP
                t["location"] = token.location
                if get_all:
                    t["user"] = token.emitted_for
                tokens_list.append(t)

        return tokens_list

    def invalidate_token(self, token):

        token_entry = self.db.Token.query.filter_by(token=token).first()
        if token_entry:
            try:
                self.db.session.delete(token_entry)
                self.db.session.commit()
                return True
            except BaseException as e:
                log.error("Could not invalidate token ({}), rolling back", e)
                self.db.session.rollback()
                return False

        log.warning("Could not invalidate token")
        return False


instance = SQLAlchemy()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: Union[Optional[str], int],
) -> "SQLAlchemy":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
