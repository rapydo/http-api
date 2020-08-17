from setuptools import find_packages, setup

from restapi import __package__ as main_package
from restapi import __version__ as current_version

app = f"{main_package}.__commands__"

setup(
    name="rapydo_http",
    version=current_version,
    description="HTTP API server working on top of the RAPyDo framework",
    url="https://rapydo.github.io/http-api",
    license="MIT",
    keywords=["http", "api", "rest", "web", "backend", "rapydo"],
    author="Paolo D'Onorio De Meo",
    author_email="p.donorio.de.meo@gmail.com",
    packages=find_packages(where=".", exclude=["tests*"]),
    package_data={
        main_package: [
            "confs/connectors.yaml",
            "models/swagger.yaml",
            "templates/index.html",
        ],
    },
    python_requires=">=3.6.0",
    entry_points=f"""
        [console_scripts]
        {main_package}={app}:cli
    """,
    install_requires=[
        # Flask and plugins
        "Flask==1.1.2",
        "Flask-RESTful==0.3.8",
        "flask-apispec==0.9.0",
        "Flask-Cors==3.0.8",
        "Flask-SQLAlchemy==2.4.4",
        "Flask-Migrate==2.5.3",
        "PyJWT",
        "pyOpenSSL",
        "passlib[bcrypt]==1.7.2",
        # DB and services drivers
        "neomodel==3.3.2",
        "psycopg2-binary",
        "pymodm",
        "PyMySQL",
        "redis",
        "pika",
        "celery",
        "flower==0.9.5",
        "celery-redbeat==1.0.0",
        "celerybeat-mongo==0.2.0",
        "python-telegram-bot==12.8",
        # TOTP
        "pyotp==2.3.0",
        "segno==1.0.0",
        # Swagger
        "bravado-core",
        "swagger-spec-validator",
        # Utilities
        "PyYAML==5.3.1",
        "loguru",
        "glom",
        "psutil",
        "plumbum",
        "maxminddb-geolite2",
        # Web sockets and others
        "websocket-client",
        "gripcontrol==4.0.0",
        "sentry-sdk[flask]==0.16.1",
        # Tests
        "pytest-flask==1.0.0",
        "pytest-cov==2.10.0",
        "schemathesis==2.1.0",
        "Faker==4.1.1",
        "Telethon==1.16.0",
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
