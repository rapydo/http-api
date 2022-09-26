#!/usr/bin/python3

from setuptools import setup

setup(
    install_requires=[
        "Flask==2.1.3",
        "flask-apispec==0.11.4",
        "Flask-Caching==2.0.1",
        "Flask-Cors==3.0.10",
        "Flask-SQLAlchemy==2.5.1",
        "Flask-Migrate==3.1.0",
        "Werkzeug==2.2.2",
        "PyJWT==2.4.0",
        "pyOpenSSL==22.0.0",
        "passlib[bcrypt]==1.7.4",
        "marshmallow==3.17.1",
        "webargs==8.2.0",
        "apispec==5.2.2",
        "neomodel==4.0.8",
        "psycopg2-binary==2.9.3",
        "PyMySQL==1.0.2",
        "redis==4.3.4",
        "pika==1.3.0",
        "celery[redis]==5.2.7",
        "flower==1.2.0",
        "celery-redbeat==2.0.0",
        "amqp==5.1.1",
        "pyotp==2.7.0",
        "segno==1.5.2",
        "PyYAML==6.0",
        "loguru==0.6.0",
        "glom==22.1.0",
        "requests==2.28.1",
        "psutil==5.9.2",
        "plumbum==1.7.2",
        "html2text==2020.1.16",
        "orjson==3.8.0",
        "sentry-sdk[flask]==1.9.9",
        "pytest==7.1.3",
        "pytest-flask==1.2.0",
        "pytest-cov==3.0.0",
        "pytest-timeout==2.1.0",
        "pytest-sugar==0.9.5",
        "Faker==14.0.0",
    ]
)
