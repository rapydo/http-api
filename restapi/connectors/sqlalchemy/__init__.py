# -*- coding: utf-8 -*-

""" Wrapper for the existing Flask-SQLalchemy

NOTE: Flask Sqlalchemy needs to have models defined on existing instance;
for this reason we create the sql instance where models are defined.

For future lazy alchemy: http://flask.pocoo.org/snippets/22/
"""

import re
from sqlalchemy import create_engine
from sqlalchemy.engine.base import Connection
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import text
from flask_migrate import Migrate
from functools import wraps
from restapi.connectors import Connector
from restapi.exceptions import DatabaseDuplicatedEntry
from restapi.utilities.meta import Meta
from restapi.confs import EXTENDED_PROJECT_DISABLED, BACKEND_PACKAGE
from restapi.confs import CUSTOM_PACKAGE, EXTENDED_PACKAGE
from restapi.utilities.logs import log


def catch_db_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        try:
            return func(*args, **kwargs)
        except DatabaseDuplicatedEntry as e:
            # already catched and parser, raise up
            raise(e)
        except IntegrityError as e:

            message = str(e).split('\n')
            if not re.search(r".*duplicate key value violates unique constraint .*",
                             message[0]):
                log.error("Unrecognized error message: {}", e)
                raise DatabaseDuplicatedEntry("Duplicated entry")

            m = re.search(
                r"DETAIL:  Key \((.+)\)=\((.+)\) already exists.",
                message[1]
            )

            if m:
                prop = m.group(1)
                val = m.group(2)
                error = "{} already exists with value: {}".format(prop.title(), val)
                raise DatabaseDuplicatedEntry(error)

            log.error("Unrecognized error message: {}", e)
            raise DatabaseDuplicatedEntry("Duplicated entry")

        except BaseException as e:
            log.critical("Raised unknown exception: {}", type(e))
            raise e

    return wrapper


class SqlAlchemy(Connector):

    def get_connection_exception(self):
        return (OperationalError,)

    def preconnect(self, **kwargs):
        return True

    def postconnect(self, obj, **kwargs):
        return True

    def connect(self, **kwargs):

        if len(kwargs) > 0:
            print("TODO: use args for connection?", kwargs)

        uri = '{}://{}:{}@{}:{}/{}'.format(
            self.variables.get('dbtype', 'postgresql'),
            self.variables.get('user'),
            self.variables.get('password'),
            self.variables.get('host'),
            self.variables.get('port'),
            self.variables.get('db'),
        )

        # TODO: in case we need different connection binds
        # (multiple connections with sql) then:
        # SQLALCHEMY_BINDS = {
        #     'users':        'mysqldb://localhost/users',
        #     'appmeta':      'sqlite:////path/to/appmeta.db'
        # }
        self.app.config['SQLALCHEMY_DATABASE_URI'] = uri

        # self.app.config['SQLALCHEMY_POOL_TIMEOUT'] = 3
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

        # pool_size = self.variables.get('poolsize')
        # if pool_size is not None:
        #     # sqlalchemy docs: http://j.mp/2xT0GOc
        #     # defaults: overflow=10, pool_size=5
        #     # self.app.config['SQLALCHEMY_MAX_OVERFLOW'] = 0
        #     self.app.config['SQLALCHEMY_POOL_SIZE'] = int(pool_size)
        #     log.debug("Setting SQLALCHEMY_POOL_SIZE = {}", pool_size)

        # search the original sqlalchemy object into models
        db = Meta.obj_from_models('db', self.name, CUSTOM_PACKAGE)

        # no 'db' set in CUSTOM_PACKAGE, looking for EXTENDED PACKAGE, if any
        if db is None and EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            db = Meta.obj_from_models('db', self.name, EXTENDED_PACKAGE)

        if db is None:
            log.warning("No sqlalchemy db imported in custom package")
            db = Meta.obj_from_models('db', self.name, BACKEND_PACKAGE)

        if db is None:
            log.exit("Could not get 'db' within {} models", self.name)

        try:

            # The Alembic package, which handles the migration work, does not recognize
            # type changes in columns by default. If you want that fine level of
            # detection you need to enable the compare_type option
            Migrate(self.app, db, compare_type=True)
        except BaseException as e:
            log.warning("Flask Migrate not enabled")
            log.error(str(e))

        # Overwrite db.session created by flask_alchemy due to errors
        # with transaction when concurrent requests...

        db.engine_bis = create_engine(uri)
        db.session = scoped_session(sessionmaker(bind=db.engine_bis))
        db.session.commit = catch_db_exceptions(db.session.commit)
        db.session.flush = catch_db_exceptions(db.session.flush)

        Connection.execute = catch_db_exceptions(Connection.execute)

        return db

    def initialize(self):

        db = self.get_instance()
        # db.init_app(self.app)

        with self.app.app_context():

            sql = text('SELECT 1')
            db.engine.execute(sql)

            db.create_all()

    def destroy(self):

        db = self.get_instance()

        with self.app.app_context():

            sql = text('SELECT 1')
            db.engine.execute(sql)

            # massive destruction
            log.critical("Destroy current SQL data")
            db.drop_all()
