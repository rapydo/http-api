# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from rapydo import __version__

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
        # FIXME: choose the right list here
        # p.s. also consider models/swagger.yaml and swagger/*
        'rapydo': ['confs/services.yaml'],
        'rapydo': ['swagger/*'],
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
        "rapydo-utils==0.4.0",
        # TODO: complete this list
        # from requirements in backend/requirements.txt
    ]
)
