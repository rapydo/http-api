from functools import lru_cache
from pathlib import Path

from glom import glom

from restapi.env import Env
from restapi.utilities.globals import mem

# ENDPOINTS bases
API_URL = "/api"
AUTH_URL = "/auth"

APP_MODE: str = Env.get("APP_MODE", "development")
FORCE_PRODUCTION_TESTS: bool = Env.get_bool("FORCE_PRODUCTION_TESTS")
TESTING: bool = APP_MODE == "test" or FORCE_PRODUCTION_TESTS
PRODUCTION: bool = APP_MODE == "production"
STACKTRACE: bool = False
REMOVE_DATA_AT_INIT_TIME: bool = False

HOSTNAME: str = Env.get("HOSTNAME", "backend-server")
# hostnames as defined in backend.yml

BACKEND_HOSTNAME = "backend-server"
FLOWER_HOSTNAME = "flower"
CELERYBEAT_HOSTNAME = "celery-beat"
BOT_HOSTNAME = "telegram-bot"
CELERY_HOSTNAME = "celery"


def get_host_type(HOSTNAME: str) -> str:

    if HOSTNAME == BACKEND_HOSTNAME:
        return BACKEND_HOSTNAME

    if HOSTNAME == FLOWER_HOSTNAME:
        return FLOWER_HOSTNAME

    if HOSTNAME == CELERYBEAT_HOSTNAME:
        return CELERYBEAT_HOSTNAME

    if HOSTNAME == BOT_HOSTNAME:
        return BOT_HOSTNAME

    # Celery has not a fixed hostname
    return CELERY_HOSTNAME


HOST_TYPE = get_host_type(HOSTNAME)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = "8080"
DATA_PATH: Path = Path(Env.get("DATA_PATH", "/uploads"))
IMPORT_PATH: Path = Path(Env.get("DATA_IMPORT_FOLDER", "/imports"))
CODE_DIR: Path = Path(Env.get("CODE_DIR", "/code"))
APP_SECRETS = Path(Env.get("APP_SECRETS", "/secrets"))
JWT_SECRET_FILE = APP_SECRETS.joinpath("jwt_secret.key")
TOTP_SECRET_FILE = APP_SECRETS.joinpath("totp_secret.key")
SSL_CERTIFICATE = "/etc/letsencrypt/real/fullchain1.pem"
DOMAIN = Env.get("DOMAIN", "")
PROXIED_CONNECTION: bool = Env.get_bool("PROXIED_CONNECTION")

MODELS_DIR = "models"
CONF_PATH = Path("confs")
# Also configured in controller
EXTENDED_PROJECT_DISABLED = "no_extended_project"
BACKEND_PACKAGE = "restapi"  # package inside rapydo-http

CUSTOM_PACKAGE = Env.get("PROJECT_NAME", "custom")
EXTENDED_PACKAGE = Env.get("EXTENDED_PACKAGE", EXTENDED_PROJECT_DISABLED)

SENTRY_URL = Env.get("SENTRY_URL", "").strip() or None

ABS_RESTAPI_PATH = Path(__file__).resolve().parent

GZIP_ENABLE = Env.get_bool("GZIP_COMPRESSION_ENABLE")
GZIP_THRESHOLD = max(0, Env.get_int("GZIP_COMPRESSION_THRESHOLD"))
GZIP_LEVEL = max(1, min(9, Env.get_int("GZIP_COMPRESSION_LEVEL")))


@lru_cache
def get_project_configuration(key: str, default: str) -> str:
    return glom(mem.configuration, key, default=default)


@lru_cache
def get_backend_url() -> str:
    if PRODUCTION:
        return f"https://{DOMAIN}"

    port = Env.get("FLASK_PORT", "8080")
    return f"http://{DOMAIN}:{port}"


@lru_cache
def get_frontend_url() -> str:
    protocol = "https" if PRODUCTION else "http"

    return f"{protocol}://{DOMAIN}"
