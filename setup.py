# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from restapi import \
    __package__ as main_package, \
    __version__ as current_version


swagger_dir = 'swagger'
app = '%s.__commands__' % main_package

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
            '%s/*.yaml' % swagger_dir,
            '%s/*/*.yaml' % swagger_dir,
            'templates/index.html',
        ],
    },
    entry_points='''
        [console_scripts]
        %s=%s:cli
    ''' % (main_package, app),
    install_requires=[
        # Rapydo framework
        "rapydo-utils==%s" % current_version,

        # Utilities
        "attrs",
        "pyOpenSSL",
        "PyJWT",

        # Flask and plugins
        "flask==1.0.2",
        "Flask-Cors",
        # Version 1.2.0 depends on OAuthlib 3.0.0 and above
        # It does not support versions of OAuthlib before 3.0.0
        # But Flask-OAuthlib depends from OAuthlib < 3.0.0
        "requests-oauthlib==1.1.0",
        "Flask-OAuthlib",
        "Flask-RESTful",
        "Flask-SQLAlchemy",
        # AssertionError: Passing keyword arguments to inject is no
        # longer supported. Use inject in combination with parameter
        # annotations to declare dependencies. :/
        # "injector==0.13.4",
        "injector==0.12",
        "flask_injector==0.10.1",

        # DB drivers

        # Do not work with 3.3.0
        # "neomodel==3.3.0",
        # "neomodel==3.3.1",
        "neomodel==3.2.9",
        "psycopg2-binary",
        "pymodm",
        "PyMySQL",

        # Swagger
        "bravado-core",
        "swagger-spec-validator",

        # Utilities
        "glom",
        "plumbum",
        "psutil",
    ],
    classifiers=[
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ]
)
