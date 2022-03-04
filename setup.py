from setuptools import find_packages, setup

from restapi import __package__ as main_package
from restapi import __version__ as current_version

app = f"{main_package}.__commands__"

setup(
    name="rapydo_http",
    version=current_version,
    description="HTTP API server working on top of the RAPyDo framework",
    url="https://rapydo.github.io/docs",
    license="MIT",
    keywords=["http", "api", "rest", "web", "backend", "rapydo"],
    packages=find_packages(where=".", exclude=["tests*"]),
    package_data={
        main_package: [
            "templates/index.html",
            "py.typed",
            "connectors/smtp/templates/*.html",
        ]
    },
    # python_requires=">=3.9.0",
    # Due to mistral (also removed str.removeprefix)
    python_requires=">=3.8.0",
    entry_points=f"""
        [console_scripts]
        {main_package}={app}:cli
    """,
    # Remember to update mypy.additional_dependencies
    install_requires=[
        # Flask, plugins and webservers
        "Flask==2.0.2",
        "Flask-RESTful==0.3.9",
        "flask-apispec==0.11.0",
        "Flask-Caching==1.10.1",
        "Flask-Cors==3.0.10",
        "Flask-SQLAlchemy==2.5.1",
        "Flask-Migrate==3.1.0",
        "PyJWT==2.3.0",
        "pyOpenSSL",
        "passlib[bcrypt]==1.7.4",
        "meinheld==1.0.2",
        "gunicorn==20.1.0",
        "marshmallow==3.14.1",
        "webargs==8.0.1",
        "apispec==5.1.1",
        # DB and services drivers
        "neomodel==4.0.8",
        "psycopg2-binary",
        "pymodm",
        "PyMySQL",
        "redis",
        "pika",
        "celery[redis]==5.2.3",
        "flower==1.0.0",
        "celery-redbeat==2.0.0",
        "celerybeat-mongo==0.2.0",
        "python-telegram-bot==13.10",
        "amqp==5.0.9",
        # TOTP
        "pyotp==2.6.0",
        "segno==1.4.1",
        # Utilities
        "PyYAML==6.0",
        "loguru",
        "glom",
        "psutil",
        "plumbum",
        "maxminddb-geolite2",
        "html2text",
        "orjson",
        "sentry-sdk[flask]==1.5.1",
        # Tests
        "pytest",
        "pytest-flask==1.2.0",
        "pytest-cov==3.0.0",
        "pytest-timeout==2.0.2",
        "pytest-sugar==0.9.4",
        "schemathesis==3.12.1",
        "Faker==11.3.0",
        "Telethon==1.24.0",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Intended Audience :: Developers",
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
    ],
)
