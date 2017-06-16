# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from rapydo import __version__
from rapydo.utils import SWAGGER_DIR

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
        "Flask",
        "Flask-Cors",
        "Flask-OAuthlib",
        "Flask-RESTful",
        "Flask-SQLAlchemy",
        "flask-shell-ipython",
        "flask_injector==v0.9.0",
        "injector==0.12.0",
        # DB drivers
        "neomodel",
        "psycopg2",
        "pymodm",
        # Swagger
        "bravado-core",
        "swagger-spec-validator",
        # Rapydo framework
        "rapydo-utils==0.4.3",
        # TODO: complete this list
        # from requirements in backend/requirements.txt
    ]
)
