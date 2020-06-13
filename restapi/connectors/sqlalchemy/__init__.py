""" Wrapper for the existing Flask-SQLalchemy

NOTE: Flask Sqlalchemy needs to have models defined on existing instance;
for this reason we create the sql instance where models are defined.

For future lazy alchemy: http://flask.pocoo.org/snippets/22/
"""

import re
from datetime import datetime, timedelta
from functools import wraps

import pytz
import sqlalchemy
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy as OriginalAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine.base import Connection
from sqlalchemy.engine.url import URL
from sqlalchemy.exc import IntegrityError, InternalError, OperationalError
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.orm.attributes import set_attribute

from restapi.connectors import Connector
from restapi.exceptions import BadRequest, DatabaseDuplicatedEntry, ServiceUnavailable
from restapi.services.authentication import NULL_IP, ROLE_DISABLED, BaseAuthentication
from restapi.utilities.logs import log
from restapi.utilities.uuid import getUUID

# all instances have to use the same alchemy object
db = OriginalAlchemy()


def catch_db_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        try:
            return func(*args, **kwargs)
        except DatabaseDuplicatedEntry:
            # already catched and parser, raise up
            raise
        except BadRequest:
            # already catched and parser, raise up
            raise
        except IntegrityError as e:

            message = str(e).split("\n")
            if not re.search(
                r".*duplicate key value violates unique constraint .*", message[0]
            ):
                log.error("Unrecognized error message: {}", e)
                raise DatabaseDuplicatedEntry("Duplicated entry")

            m = re.search(r"DETAIL:  Key \((.+)\)=\((.+)\) already exists.", message[1])

            if m:
                prop = m.group(1)
                val = m.group(2)
                error = f"{prop.title()} already exists with value: {val}"
                raise DatabaseDuplicatedEntry(error)

            log.error("Unrecognized error message: {}", e)
            raise DatabaseDuplicatedEntry("Duplicated entry")

        except InternalError as e:

            message = str(e)

            m = re.search(
                r"Incorrect string value: '(.*)' for column `.*`.`.*`.`(.*)` at row .*",
                message,
            )

            if m:
                value = m.group(1)
                column = m.group(2)
                error = f"Invalid {column}: {value}"
                raise BadRequest(error)

            log.error("Unrecognized error message: {}", message)
            raise

        except BaseException as e:
            log.critical("Raised unknown exception {}: {}", e.__class__.__name__, e)
            raise

    return wrapper


class SQLAlchemy(Connector):
    def get_connection_exception(self):
        return (OperationalError,)

    def connect(self, test_connection=False, **kwargs):

        variables = self.variables.copy()
        variables.update(kwargs)

        db_url = {
            "database": variables.get("db"),
            "drivername": variables.get("dbtype", "postgresql"),
            "username": variables.get("user"),
            "password": variables.get("password"),
            "host": variables.get("host"),
            "port": variables.get("port"),
        }

        if variables.get("dbtype", "postgresql") == "mysql+pymysql":
            db_url["query"] = {"charset": "utf8mb4"}

        uri = URL(**db_url)
        # TODO: in case we need different connection binds
        # (multiple connections with sql) then:
        # SQLALCHEMY_BINDS = {
        #     'users':        'mysqldb://localhost/users',
        #     'appmeta':      'sqlite:////path/to/appmeta.db'
        # }
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
        db.update_properties = self.update_properties
        db.disconnect = self.disconnect

        Connection.execute = catch_db_exceptions(Connection.execute)

        db.init_app(self.app)

        if test_connection:
            sql = text("SELECT 1")
            db.engine.execute(sql)
        self.db = db
        return db

    def disconnect(self):
        return

    def __enter__(self):
        return self

    def __exit__(self, _type, value, tb):
        self.disconnect()

    def initialize(self):

        db = self.get_instance()

        with self.app.app_context():

            sql = text("SELECT 1")
            db.engine.execute(sql)

            db.create_all()

    def destroy(self):

        db = self.get_instance()

        with self.app.app_context():

            sql = text("SELECT 1")
            db.engine.execute(sql)

            db.session.remove()
            db.session.close_all()
            # massive destruction
            log.critical("Destroy current SQL data")
            db.drop_all()

    @staticmethod
    def update_properties(instance, schema, properties):

        for field in schema:
            if isinstance(field, str):
                key = field
            else:
                # to be deprecated
                if "custom" in field:
                    if "islink" in field["custom"]:
                        if field["custom"]["islink"]:
                            continue
                key = field["name"]

            if key in properties:
                set_attribute(instance, key, properties[key])


class Authentication(BaseAuthentication):

    # Also used by POST user
    def create_user(self, userdata, roles):

        userdata.setdefault("authmethod", "credentials")
        userdata.setdefault("uuid", getUUID())

        if "password" in userdata:
            userdata["password"] = self.get_password_hash(userdata["password"])

        userdata = self.custom_user_properties(userdata)

        user = self.db.User(**userdata)
        self.link_roles(user, roles)

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

    def get_user_object(self, username=None, payload=None):
        user = None
        try:
            if username is not None:
                user = self.db.User.query.filter_by(email=username).first()
            if payload is not None and "user_id" in payload:
                user = self.db.User.query.filter_by(uuid=payload["user_id"]).first()
        except (sqlalchemy.exc.StatementError, sqlalchemy.exc.InvalidRequestError) as e:

            # Unable to except pymysql.err.OperationalError because:
            # ModuleNotFoundError: No module named 'pymysql.err.OperationalError';
            # 'pymysql.err' is not a package
            # Let's test exception name (OMG!)
            if type(e).__name__ == "pymysql.err.OperationalError":
                # If you catch an error that indicates the connection was closed during
                # an operation, SQLAlchemy automatically reconnects on the next access.

                # Pessimistic approach: Add pool_pre_ping=True when creating the engine
                # The “pre ping” feature will normally emit SQL equivalent to “SELECT 1”
                # each time a connection is checked out from the pool; if an error is
                # raised that is detected as a “disconnect” situation, the connection
                # will be immediately recycled, and all other pooled connections older
                # than the current time are invalidated, so that the next time they are
                # checked out, they will also be recycled before use.
                # This add a little overhead to every connections
                # https://docs.sqlalchemy.org/en/13/core/pooling.html#pool-disconnects-pessimistic

                # Optimistic approach: try expect for connection errors.
                # When the connection attempts to use a closed connection an exception
                # is raised, then the connection calls the Pool.create() method,
                # further connections will work again by using the refreshed connection.
                # Only a single transaction will fail -> retry the operation is enough
                # https://docs.sqlalchemy.org/en/13/core/pooling.html#disconnect-handling-optimistic

                # if retry <= 0:
                #     log.error(str(e))
                #     log.warning("Errors retrieving user object, retrying...")
                #     return self.get_user_object(
                #         username=username, payload=payload, retry=1
                #     )
                raise e
            else:
                log.error(str(e))
                raise ServiceUnavailable("Backend database is unavailable")
        except (sqlalchemy.exc.DatabaseError, sqlalchemy.exc.OperationalError) as e:
            # if retry <= 0:
            #     log.error(str(e))
            #     log.warning("Errors retrieving user object, retrying...")
            #     return self.get_user_object(
            #         username=username, payload=payload, retry=1)
            raise e

        return user

    def get_users(self, user_id=None):

        # Retrieve all
        if user_id is None:
            return self.db.User.query.all()

        # Retrieve one
        user = self.db.User.query.filter_by(uuid=user_id).first()
        if user is None:
            return None

        return [user]

    def get_roles(self):
        roles = []
        for role_name in self.roles:
            role = self.db.Role.query.filter_by(name=role_name).first()
            roles.append(role)

        return roles

    def get_roles_from_user(self, userobj=None):

        roles = []
        if userobj is None:
            try:
                userobj = self.get_user()
            except Exception as e:
                log.warning("Roles check: invalid current user.\n{}", e)
                return roles

        # No user for on authenticated endpoints -> return no role
        if userobj is None:
            return roles

        for role in userobj.roles:
            roles.append(role.name)
        return roles

    # TODO: (IMPORTANT) developer should be able to specify a custom init
    # which would replace this function below
    def init_users_and_roles(self):

        missing_role = missing_user = False

        try:
            # if no roles
            missing_role = not self.db.Role.query.first()
            if missing_role:
                for role_name in self.roles:
                    role_description = self.roles_data.get(role_name, ROLE_DISABLED)
                    role = self.db.Role(name=role_name, description=role_description)
                    self.db.session.add(role)
                log.info("Injected default roles")

            # if no users
            missing_user = not self.db.User.query.first()
            if missing_user:
                self.create_user(
                    {
                        "email": self.default_user,
                        # 'authmethod': 'credentials',
                        "name": "Default",
                        "surname": "User",
                        "password": self.default_password,
                    },
                    roles=self.roles,
                )
                log.info("Injected default user")

            if missing_user or missing_role:
                self.db.session.commit()
        except sqlalchemy.exc.OperationalError:
            self.db.session.rollback()
            # A migration / rebuild is required?
            raise AttributeError("Inconsistences between DB schema and data models")

    def save_user(self, user):
        if user is not None:
            self.db.session.add(user)
            self.db.session.commit()

    def save_token(self, user, token, payload, token_type=None):
        # payload['jti']
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

            log.verbose("Token stored inside the DB")
        except BaseException as e:
            log.error("DB error ({}), rolling back", e)
            self.db.session.rollback()

    def verify_token_validity(self, jti, user):

        token_entry = self.db.Token.query.filter_by(jti=jti).first()

        if token_entry is None:
            return False
        if token_entry.user_id is None or token_entry.user_id != user.id:
            return False

        # MySQL seems unable to save tz-aware datetimes...
        if token_entry.expiration.tzinfo is None:
            # Create a offset-naive datetime
            now = datetime.now()
        else:
            # Create a offset-aware datetime
            now = datetime.now(pytz.utc)

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
        elif user is not None:
            tokens = user.tokens.all()
        elif token_jti is not None:
            tokens = [self.db.Token.query.filter_by(jti=token_jti).first()]

        if tokens is None:
            return tokens_list

        for token in tokens:

            if token is None:
                continue

            t = {}

            t["id"] = token.jti
            t["token"] = token.token
            t["token_type"] = token.token_type
            # t["emitted"] = token.creation.strftime('%s')
            # t["last_access"] = token.last_access.strftime('%s')
            # if token.expiration is not None:
            #     t["expiration"] = token.expiration.strftime('%s')
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
        if token_entry is not None:
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
