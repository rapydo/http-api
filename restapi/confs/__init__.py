# -*- coding: utf-8 -*-

import os
import re
from urllib.parse import urlparse

from glom import glom

from restapi.utilities.globals import mem

STACKTRACE = False
REMOVE_DATA_AT_INIT_TIME = False

#################
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
UPLOAD_FOLDER = os.environ.get('UPLOAD_PATH', '/uploads')
SECRET_KEY_FILE = os.environ.get('JWT_APP_SECRETS') + "/secret.key"

#################
PRODUCTION = os.environ.get('APP_MODE', '') == 'production'

SWAGGER_DIR = 'swagger'
MODELS_DIR = 'models'
CONF_PATH = 'confs'
# Also configured in controller
EXTENDED_PROJECT_DISABLED = "no_extended_project"
BACKEND_PACKAGE = 'restapi'  # package inside rapydo-http

CUSTOM_PACKAGE = os.environ.get('VANILLA_PACKAGE', 'custom')
EXTENDED_PACKAGE = os.environ.get('EXTENDED_PACKAGE', None)
#################
# SQLALCHEMY
BASE_DB_DIR = '/dbs'
SQLLITE_EXTENSION = 'db'
SQLLITE_DBFILE = 'backend' + '.' + SQLLITE_EXTENSION
dbfile = os.path.join(BASE_DB_DIR, SQLLITE_DBFILE)
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + dbfile

SENTRY_URL = os.environ.get('SENTRY_URL')
if SENTRY_URL is not None and SENTRY_URL.strip() == '':
    SENTRY_URL = None

ABS_RESTAPI_CONFSPATH = os.path.dirname(os.path.realpath(__file__))
ABS_RESTAPI_PATH = os.path.dirname(ABS_RESTAPI_CONFSPATH)


def get_project_configuration(key=None, default=None):
    if key is None:
        return mem.customizer._configurations
    return glom(mem.customizer._configurations, key, default=default)


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
