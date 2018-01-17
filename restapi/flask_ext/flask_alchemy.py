# -*- coding: utf-8 -*-

""" Alchemy extension wrapper
for the existing Flask-SQLalchemy

NOTE: Flask Sqlalchemy needs to have models defined on existing instance;
for this reason we create the sql instance where models are defined.

For future lazy alchemy: http://flask.pocoo.org/snippets/22/
"""

import sqlalchemy
from utilities.meta import Meta
from utilities import BACKEND_PACKAGE, CUSTOM_PACKAGE
from restapi.flask_ext import BaseExtension, get_logger
from utilities.logs import re_obscure_pattern

log = get_logger(__name__)


class SqlAlchemy(BaseExtension):

    def set_connection_exception(self):
        return (sqlalchemy.exc.OperationalError, )

    def custom_connection(self, **kwargs):

        if len(kwargs) > 0:
            print("TODO: use args for connection?", kwargs)

        uri = 'postgresql://%s:%s@%s:%s/%s' % (
            self.variables.get('user'),
            self.variables.get('password'),
            self.variables.get('host'),
            self.variables.get('port'),
            self.variables.get('db')
        )

        log.very_verbose("URI IS %s" % re_obscure_pattern(uri))

        # TODO: in case we need different connection binds
        # (multiple connections with sql) then:
        # SQLALCHEMY_BINDS = {
        #     'users':        'mysqldb://localhost/users',
        #     'appmeta':      'sqlite:////path/to/appmeta.db'
        # }

        self.app.config['SQLALCHEMY_POOL_TIMEOUT'] = 3
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['SQLALCHEMY_DATABASE_URI'] = uri

        pool_size = self.variables.get('poolsize')
        if pool_size is not None:
            # sqlalchemy docs: http://j.mp/2xT0GOc
            # defaults: overflow=10, pool_size=5
            self.app.config['SQLALCHEMY_MAX_OVERFLOW'] = 0
            self.app.config['SQLALCHEMY_POOL_SIZE'] = int(pool_size)

        obj_name = 'db'
        m = Meta()
        # search the original sqlalchemy object into models
        db = m.obj_from_models(obj_name, self.name, CUSTOM_PACKAGE)
        if db is None:
            log.warning("No sqlalchemy db imported in custom package")
            db = m.obj_from_models(obj_name, self.name, BACKEND_PACKAGE)
        if db is None:
            log.critical_exit(
                "Could not get %s within %s models" % (obj_name, self.name))

        return db

    def custom_init(self, pinit=False, pdestroy=False, **kwargs):
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
