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
    package_data={main_package: ["templates/index.html"]},
    python_requires=">=3.6.0",
    entry_points=f"""
        [console_scripts]
        {main_package}={app}:cli
    """,
    install_requires=[
        # Flask and plugins
        "Flask==1.1.2",
        "Flask-RESTful==0.3.8",
        "flask-apispec==0.10.0",
        "Flask-Cors==3.0.9",
        "Flask-SQLAlchemy==2.4.4",
        "Flask-Migrate==2.5.3",
        # Removed me after flask-apispec will have fixed the requirements
        "apispec==3.3.2",
        "PyJWT",
        "pyOpenSSL",
        "passlib[bcrypt]==1.7.2",
        # DB and services drivers
        "neomodel==4.0.0",
        "psycopg2-binary",
        "pymodm",
        "PyMySQL",
        "redis",
        "pika",
        "celery==4.4.7",
        "flower==0.9.5",
        "celery-redbeat==1.0.0",
        "celerybeat-mongo==0.2.0",
        "python-telegram-bot==12.8",
        # TOTP
        "pyotp==2.4.0",
        "segno==1.3.1",
        # Utilities
        "PyYAML==5.3.1",
        "loguru",
        "glom",
        "psutil",
        "plumbum",
        "maxminddb-geolite2",
        # Used by Marshmallow to serialize Decimals
        "simplejson",
        # Web sockets and others
        "websocket-client",
        "gripcontrol==4.0.0",
        "sentry-sdk[flask]==0.17.6",
        # Tests
        "pytest-flask==1.0.0",
        "pytest-cov==2.10.1",
        "pytest-timeout==1.4.2",
        "schemathesis==2.4.1",
        "Faker==4.1.3",
        "Telethon==1.16.4",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Intended Audience :: Developers",
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
)
