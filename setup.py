# -*- coding: utf-8 -*-

# this created a lot of difficulties
# from utilities import __version__ as current_version, SWAGGER_DIR
from setuptools import setup, find_packages
from restapi import \
    __package__ as main_package, \
    __version__ as current_version


swagger_dir = 'swagger'

app = '%s.__main__:main' % main_package

setup(
    name='rapydo_http',
    version=current_version,
    url='https://rapydo.github.io/http-api',
    license='MIT',
    keywords=['http', 'api', 'rest', 'web', 'backend', 'rapydo'],
    packages=find_packages(
        where='.',
        exclude=['test*']
    ),
    package_data={
        'rapydo': [
            'confs/services.yaml',
            '%s/*.yaml' % swagger_dir,
            '%s/*/*.yaml' % swagger_dir,
        ],
    },
    # # TODO: investigate
    # entry_points={
    #     'console_scripts': [
    #         'develop = %s' % app,
    install_requires=[
        # Rapydo framework
        "rapydo-utils==%s" % current_version,
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
    ],
    # FIXME: import from utils
    author="Paolo D'Onorio De Meo",
    author_email='p.donorio.de.meo@gmail.com',
    # FIXME: import from utils
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
