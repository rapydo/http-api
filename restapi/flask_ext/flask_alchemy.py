# -*- coding: utf-8 -*-

""" Alchemy extension wrapper
for the existing Flask-SQLalchemy

NOTE: Flask Sqlalchemy needs to have models defined on existing instance;
for this reason we create the sql instance where models are defined.

For future lazy alchemy: http://flask.pocoo.org/snippets/22/
"""

import sqlalchemy
from restapi.utilities.meta import Meta
from restapi.confs import EXTENDED_PROJECT_DISABLED, BACKEND_PACKAGE
from restapi.confs import CUSTOM_PACKAGE, EXTENDED_PACKAGE
from restapi.flask_ext import BaseExtension
from restapi.utilities.logs import log


class SqlAlchemy(BaseExtension):
    def set_connection_exception(self):
        return (sqlalchemy.exc.OperationalError,)

    def custom_connection(self, **kwargs):

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

        obj_name = 'db'
        # search the original sqlalchemy object into models
        db = Meta.obj_from_models(obj_name, self.name, CUSTOM_PACKAGE)

        try:
            from flask_migrate import Migrate

            # The Alembic package, which handles the migration work, does not recognize
            # type changes in columns by default. If you want that fine level of
            # detection you need to enable the compare_type option
            Migrate(self.app, db, compare_type=True)
        except BaseException as e:
            log.warning("Flask Migrate not enabled")
            log.error(str(e))

        # no 'db' set in CUSTOM_PACKAGE, looking for EXTENDED PACKAGE, if any
        if db is None and EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            db = Meta.obj_from_models(obj_name, self.name, EXTENDED_PACKAGE)

        if db is None:
            log.warning("No sqlalchemy db imported in custom package")
            db = Meta.obj_from_models(obj_name, self.name, BACKEND_PACKAGE)
        if db is None:
            log.exit("Could not get {} within {} models", obj_name, self.name)

        # Overwrite db.session created by flask_alchemy due to errors
        # with transaction when concurrent requests...
        from sqlalchemy import create_engine
        from sqlalchemy.orm import scoped_session
        from sqlalchemy.orm import sessionmaker

        db.engine_bis = create_engine(uri)
        db.session = scoped_session(sessionmaker(bind=db.engine_bis))

        return db

    def custom_init(self, pinit=False, pdestroy=False, abackend=None, **kwargs):
        """ Note: we ignore args here """

        # recover instance with the parent method
        db = super().custom_init()

        # do init_app on the original flask sqlalchemy extension
        db.init_app(self.app)

        # careful on what you do with app context on sqlalchemy
        with self.app.app_context():

            # check connection
            from sqlalchemy import text

            sql = text('SELECT 1')
            db.engine.execute(sql)

            if pdestroy:
                # massive destruction
                log.critical("Destroy current SQL data")
                db.drop_all()

            if pinit:
                # all is fine: now create table
                # because they should not exist yet
                db.create_all()

        return db
