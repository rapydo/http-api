# -*- coding: utf-8 -*-

import os
import re
from flask import request
from urllib.parse import urlparse

AVOID_COLORS_ENV_LABEL = 'TESTING_FLASK'
STACKTRACE = False
REMOVE_DATA_AT_INIT_TIME = False
#################################
# ENDPOINTS bases
API_URL = '/api'
AUTH_URL = '/auth'
STATIC_URL = '/static'
BASE_URLS = [API_URL, AUTH_URL]
#################################
# Directories for core code or user custom code
BACKEND_PACKAGE = 'rapydo'
CUSTOM_PACKAGE = os.environ.get('VANILLA_PACKAGE', 'custom')
CORE_CONFIG_PATH = os.path.join(BACKEND_PACKAGE, 'confs')
PROJECT_CONF_FILE = 'project_configuration'
# BLUEPRINT_KEY = 'blueprint'
#################################
# THE APP
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = '5000'
USER_HOME = os.environ['HOME']
UPLOAD_FOLDER = '/uploads'
SECRET_KEY_FILE = os.environ.get('JWT_APP_SECRETS') + "/secret.key"
PRODUCTION = False
# DEBUG = False
if os.environ.get('APP_MODE', '') == 'production':
    PRODUCTION = True
# elif os.environ.get('APP_MODE', '') == 'debug':
#     DEBUG = True

#################################
# SQLALCHEMY
BASE_DB_DIR = '/dbs'
SQLLITE_EXTENSION = 'db'
SQLLITE_DBFILE = 'backend' + '.' + SQLLITE_EXTENSION
dbfile = os.path.join(BASE_DB_DIR, SQLLITE_DBFILE)
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + dbfile


########################################
def get_api_url():
    """ Get api URL and PORT

    Usefull to handle https and similar
    unfiltering what is changed from nginx and container network configuration

    Warning: it works only if called inside a Flask endpoint
    """

    api_url = request.url_root

    if PRODUCTION:
        parsed = urlparse(api_url)
        if parsed.port is not None and parsed.port == 443:
            removed_port = re.sub(r':[\d]+$', '', parsed.netloc)
            api_url = parsed._replace(
                scheme="https", netloc=removed_port
            ).geturl()

    return api_url
