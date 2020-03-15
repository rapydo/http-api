# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from restapi import \
    __package__ as main_package, \
    __version__ as current_version


app = '{}.__commands__'.format(main_package)

setup(
    name='rapydo_http',
    version=current_version,
    description='HTTP API server working on top of the RAPyDo framework',
    url='https://rapydo.github.io/http-api',
    license='MIT',
    keywords=['http', 'api', 'rest', 'web', 'backend', 'rapydo'],
    author="Paolo D'Onorio De Meo",
    author_email='p.donorio.de.meo@gmail.com',
    packages=find_packages(
        where='.',
        exclude=['tests*']
    ),
    package_data={
        main_package: [
            'confs/services.yaml',
            'models/swagger.yaml',
            'templates/index.html'
        ],
    },
    entry_points='''
        [console_scripts]
        {}={}:cli
    '''.format(main_package, app),
    install_requires=[
        # Flask and plugins
        "Flask==1.1.1",
        "Flask-RESTful==0.3.8",
        "flask-apispec==0.8.5",
        "Flask-Cors==3.0.8",
        "Flask-SQLAlchemy==2.4.1",
        "Flask-Migrate",
        "uWSGI",

        "PyJWT",
        "pyOpenSSL",
        "passlib[bcrypt]==1.7.2",
        "authlib==0.13",

        "PyYAML==5.3",

        # DB and services drivers
        "neomodel>=3.2.9, <=3.3.2",
        "psycopg2-binary",
        "pymodm",
        "PyMySQL",
        "redis",
        "pika",
        "celery",
        "flower==0.9.3",
        "celery-redbeat==0.13.0",
        # "celerybeat-mongo @ git+https://github.com/zmap/celerybeat-mongo.git@master",
        "celerybeat-mongo==0.2.0",

        # Swagger
        "bravado-core",
        "swagger-spec-validator",

        # Utilities
        "attrs",
        "loguru",
        "glom",
        "psutil",
        "plumbum",
        "pretty_errors",
        "maxminddb-geolite2",

        # Web sockets
        "websocket-client",
        "gripcontrol==4.0.0",

        # Sentry
        "sentry-sdk[flask]==0.14.0"
    ],
    classifiers=[
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ]
)
