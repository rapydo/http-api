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
        # Utilities
        "attrs",
        "pyOpenSSL",
        "PyJWT",

        # Flask and plugins
        "Flask==1.1.1",
        "Flask-Cors==3.0.8",

        # Latest requests-oauthlib [1.2.0] (required by Flask-OAuthlib)
        # requires oauthlib<3.0.0,>=2.1.0
        "oauthlib==2.1.0",
        # Version 1.2.0 depends on OAuthlib 3.0.0 and above
        # It does not support versions of OAuthlib before 3.0.0
        # But Flask-OAuthlib depends from OAuthlib < 3.0.0
        "requests-oauthlib==1.1.0",
        "Flask-OAuthlib==0.9.5",

        "Flask-RESTful==0.3.7",
        "Flask-SQLAlchemy==2.4.1",
        # AssertionError: Passing keyword arguments to inject is no
        # longer supported. Use inject in combination with parameter
        # annotations to declare dependencies. :/
        # "injector==0.17",
        "injector==0.12",
        "flask_injector==0.11.0",

        "PyYAML==5.2",

        # DB drivers
        "neomodel>=3.2.9, <=3.3.2",
        "psycopg2-binary",
        "pymodm",
        "PyMySQL",

        # Swagger
        "bravado-core",
        "swagger-spec-validator",

        # Utilities
        "loguru",
        "glom",
        "psutil",
        "plumbum",
        "better_exceptions",
        "maxminddb-geolite2"
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
