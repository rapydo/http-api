#!/usr/bin/python3

from setuptools import setup

setup(
    install_requires=[
        "Flask==2.1.1",
        "flask-apispec==0.11.1",
        "Flask-Caching==1.10.1",
        "Flask-Cors==3.0.10",
        "Flask-SQLAlchemy==2.5.1",
        "Flask-Migrate==3.1.0",
        "Werkzeug==2.1.0",
        "gunicorn==20.1.0",
        "PyJWT==2.3.0",
        "pyOpenSSL",
        "passlib[bcrypt]==1.7.4",
        "marshmallow==3.15.0",
        "webargs==8.1.0",
        "apispec==5.2.2",
        "neomodel==4.0.8",
        "psycopg2-binary",
        "PyMySQL",
        "redis==4.2.2",
        "pika",
        "celery[redis]==5.2.3",
        "flower==1.0.0",
        "celery-redbeat==2.0.0",
        "amqp==5.1.0",
        "pyotp==2.6.0",
        "segno==1.4.1",
        "PyYAML==6.0",
        "loguru",
        "glom",
        "psutil",
        "plumbum",
        "maxminddb-geolite2",
        "html2text",
        "orjson",
        "sentry-sdk[flask]==1.5.11",
        "pytest",
        "pytest-flask==1.2.0",
        "pytest-cov==3.0.0",
        "pytest-timeout==2.1.0",
        "pytest-sugar==0.9.4",
        "schemathesis==3.13.7",
        "Faker==13.3.3",
    ]
)
