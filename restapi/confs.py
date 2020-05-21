# -*- coding: utf-8 -*-

import os
import re
from urllib.parse import urlparse
from functools import lru_cache

from glom import glom

from restapi.utilities.globals import mem

APP_MODE = os.getenv('APP_MODE', 'debug')
TESTING = APP_MODE == 'test'
PRODUCTION = APP_MODE == 'production'
STACKTRACE = False
REMOVE_DATA_AT_INIT_TIME = False

# ENDPOINTS bases
API_URL = '/api'
AUTH_URL = '/auth'
STATIC_URL = '/static'
BASE_URLS = [API_URL, AUTH_URL]

#################
# THE APP
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = '8080'
USER_HOME = os.environ['HOME']
UPLOAD_PATH = os.getenv('UPLOAD_PATH')
SECRET_KEY_FILE = os.getenv('JWT_APP_SECRETS') + "/secret.key"

#################

MODELS_DIR = 'models'
CONF_PATH = 'confs'
# Also configured in controller
EXTENDED_PROJECT_DISABLED = "no_extended_project"
BACKEND_PACKAGE = 'restapi'  # package inside rapydo-http

CUSTOM_PACKAGE = os.getenv('VANILLA_PACKAGE', 'custom')
EXTENDED_PACKAGE = os.getenv('EXTENDED_PACKAGE', None)
#################
# SQLALCHEMY
BASE_DB_DIR = '/dbs'
SQLLITE_DBFILE = 'backend.db'
dbfile = os.path.join(BASE_DB_DIR, SQLLITE_DBFILE)
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + dbfile

SENTRY_URL = os.getenv('SENTRY_URL')
if SENTRY_URL is not None and SENTRY_URL.strip() == '':
    SENTRY_URL = None

ABS_RESTAPI_CONFSPATH = os.path.dirname(os.path.realpath(__file__))
ABS_RESTAPI_PATH = os.path.dirname(ABS_RESTAPI_CONFSPATH)


@lru_cache
def get_project_configuration(key, default=None):
    return glom(mem.configuration, key, default=default)


def get_api_url(request_object, production=False):
    """ Get api URL and PORT

    Usefull to handle https and similar
    unfiltering what is changed from nginx and container network configuration

    Warning: it works only if called inside a Flask endpoint
    """

    api_url = request_object.url_root

    if production:
        parsed = urlparse(api_url)
        if parsed.port is not None and parsed.port == 443:
            removed_port = re.sub(r':[\d]+$', '', parsed.netloc)
            api_url = parsed._replace(scheme="https", netloc=removed_port).geturl()

    return api_url
