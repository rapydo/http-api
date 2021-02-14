import os
from functools import lru_cache
from pathlib import Path

from glom import glom

from restapi.env import Env
from restapi.utilities.globals import mem

APP_MODE: str = os.getenv("APP_MODE", "development")
FORCE_PRODUCTION_TESTS: bool = Env.get_bool("FORCE_PRODUCTION_TESTS")
TESTING: bool = APP_MODE == "test" or FORCE_PRODUCTION_TESTS
PRODUCTION: bool = APP_MODE == "production"
STACKTRACE: bool = False
REMOVE_DATA_AT_INIT_TIME: bool = False

# ENDPOINTS bases
API_URL = "/api"
AUTH_URL = "/auth"
STATIC_URL = "/static"
BASE_URLS = [API_URL, AUTH_URL]

#################
# THE APP
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = "8080"
USER_HOME = os.environ["HOME"]
UPLOAD_PATH = os.getenv("UPLOAD_PATH", "/upload")
SECRET_KEY_FILE = f"{os.getenv('JWT_APP_SECRETS')}/secret.key"

#################

MODELS_DIR = "models"
CONF_PATH = Path("confs")
# Also configured in controller
EXTENDED_PROJECT_DISABLED = "no_extended_project"
BACKEND_PACKAGE = "restapi"  # package inside rapydo-http

CUSTOM_PACKAGE = os.getenv("VANILLA_PACKAGE", "custom")
EXTENDED_PACKAGE = os.getenv("EXTENDED_PACKAGE", EXTENDED_PROJECT_DISABLED)
#################
# SQLALCHEMY
BASE_DB_DIR = "/dbs"
SQLLITE_DBFILE = "backend.db"
dbfile = os.path.join(BASE_DB_DIR, SQLLITE_DBFILE)
SQLALCHEMY_DATABASE_URI = f"sqlite:///{dbfile}"

SENTRY_URL = os.getenv("SENTRY_URL")
if SENTRY_URL is not None and SENTRY_URL.strip() == "":
    SENTRY_URL = None

ABS_RESTAPI_PATH = os.path.dirname(os.path.realpath(__file__))

GZIP_ENABLE = Env.get_bool("GZIP_COMPRESSION_ENABLE")
GZIP_THRESHOLD = max(0, Env.get_int("GZIP_COMPRESSION_THRESHOLD"))
GZIP_LEVEL = max(1, min(9, Env.get_int("GZIP_COMPRESSION_LEVEL")))


@lru_cache
def get_project_configuration(key, default=None):
    return glom(mem.configuration, key, default=default)


@lru_cache
def get_backend_url():
    domain = os.getenv("DOMAIN")
    if PRODUCTION:
        return f"https://{domain}"

    port = os.getenv("FLASK_PORT")
    return f"http://{domain}:{port}"


@lru_cache
def get_frontend_url():
    domain = os.getenv("DOMAIN")
    protocol = "https" if PRODUCTION else "http"

    return f"{protocol}://{domain}"
