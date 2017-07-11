# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from rapydo import __version__
# from rapydo.utils import SWAGGER_DIR
SWAGGER_DIR = 'swagger'

setup(
    name='rapydo_http',
    version=__version__,
    author="Paolo D'Onorio De Meo",
    author_email='p.donorio.de.meo@gmail.com',
    url='https://github.com/rapydo/http-api',
    license='MIT',
    # flask_ext & rapydo ?
    packages=find_packages(
        where='.',
        exclude=['test*', 'rapydo.OLD*']
    ),
    package_data={
        'rapydo': [
            'confs/services.yaml',
            '%s/*.yaml' % SWAGGER_DIR,
            '%s/*/*.yaml' % SWAGGER_DIR,
        ],
    },
    install_requires=[
        # various utilities
        "attrs",
        "better_exceptions",
        "pyOpenSSL",
        "PyJWT",
        # Flask and plugins
        "Flask==0.12.2",
        "Flask-Cors",
        "Flask-OAuthlib",
        "Flask-RESTful",
        "Flask-SQLAlchemy",
        # FIXME: check if this could be removed
        "flask-shell-ipython",
        "flask_injector==v0.9.0",
        "injector==0.12.0",
        # DB drivers
        "neomodel==3.2.5",
        "psycopg2",
        "pymodm",
        # FS
        "python-irodsclient==0.6.0",
        "gssapi==1.2.0",
        # Swagger
        "bravado-core",
        "swagger-spec-validator",
        # Rapydo framework
        "rapydo-utils==0.4.7",
        # TODO: complete this list
        # from requirements in backend/requirements.txt
    ]
)
