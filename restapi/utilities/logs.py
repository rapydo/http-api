# -*- coding: utf-8 -*-

import os
import sys
import json
import urllib
import re
from loguru import logger as log

from restapi.confs import PRODUCTION


log_level = os.environ.get('DEBUG_LEVEL', 'DEBUG')
LOGS_FOLDER = "/logs"
HOSTNAME = os.environ.get("HOSTNAME", "backend")
CONTAINER_ID = os.environ.get("CONTAINER_ID", "")
IS_CELERY_CONTAINER = os.environ.get("IS_CELERY_CONTAINER", "0")

# BACKEND-SERVER
if IS_CELERY_CONTAINER == '0':
    LOGS_FILE = HOSTNAME
# Flower or Celery-Beat
elif HOSTNAME != CONTAINER_ID:
    LOGS_FILE = HOSTNAME
# Celery (variables name due to scaling)
else:
    LOGS_FILE = "celery_{}".format(HOSTNAME)

LOGS_PATH = os.path.join(LOGS_FOLDER, "{}.log".format(LOGS_FILE))

log.level("VERBOSE", no=1, color="<fg #666>")
log.level("INFO", color="<green>")


def get_logger(not_used):
    # Deprecated since 0.7.1
    log.warning("Deprecated get_logger, import log instead")
    return log


def verbose(*args, **kwargs):
    log.log("VERBOSE", *args, **kwargs)


def critical_exit(message="", *args, **kwargs):
    error_code = kwargs.pop('error_code', 1)
    if not isinstance(error_code, int):
        raise ValueError("Error code must be an integer")
    if error_code < 1:
        raise ValueError("Cannot exit with value below 1")

    log.critical(message, *args, **kwargs)
    sys.exit(error_code)


log.verbose = verbose
log.exit = critical_exit

log.remove()


# Prevent exceptions on standard sink
def print_message_on_stderr(record):
    return record.get("exception") is None


fmt = ""
fmt += "<fg #FFF>{time:YYYY-MM-DD HH:mm:ss,SSS}</fg #FFF> "
fmt += "[<level>{level}</level> "
fmt += "<fg #666>{name}:{line}</fg #666>] "
fmt += "<fg #FFF>{message}</fg #FFF>"

log.add(
    sys.stderr,
    level=log_level,
    colorize=True,
    format=fmt,
    # If True the exception trace is extended upward, beyond the catching point
    # to show the full stacktrace which generated the error.
    backtrace=False,
    # Display variables values in exception trace to eases the debugging.
    # Disabled in production to avoid leaking sensitive data.
    # Note: enabled in development mode on the File Logger
    diagnose=False,
    filter=print_message_on_stderr
)

if LOGS_PATH is not None:
    try:
        log.add(
            LOGS_PATH,
            level="WARNING",
            rotation="1 week",
            retention="4 weeks",
            # If True the exception trace is extended upward, beyond the catching point
            # to show the full stacktrace which generated the error.
            backtrace=False,
            # Display variables values in exception trace to eases the debugging.
            # Disabled in production to avoid leaking sensitive data.
            diagnose=not PRODUCTION,
            # Messages pass through a multiprocess-safe queue before reaching the sink
            # This is useful while logging to a file through multiple processes.
            # This also has the advantage of making logging calls non-blocking.
            # Unfortunately it fails to serialize some exceptions with pickle
            enqueue=False,
            # Errors occurring while sink handles logs messages are automatically caught
            # an exception message is displayed on sys.stderr but the exception
            # is not propagated to the caller, preventing your app to crash.
            # This is the case when picle fails to serialize before sending to the queue
            catch=True,
        )
    except PermissionError as p:
        log.error(p)
        LOGS_PATH = None

# Logs utilities


MAX_CHAR_LEN = 200
OBSCURE_VALUE = '****'
OBSCURED_FIELDS = [
    'password',
    'pwd',
    'token',
    'access_token',
    'file',
    'filename',
    'new_password',
    'password_confirm',
]


# def re_obscure_pattern(string):

#     patterns = {'http_credentials': r'[^:]+\:([^@:]+)\@[^:]+:[^:]'}

#     for _, pattern in patterns.items():
#         p = re.compile(pattern)
#         m = p.search(string)
#         if m:
#             g = m.group(1)
#             string = string.replace(g, OBSCURE_VALUE)

#     return string


def handle_log_output(original_parameters_string):
    """ Avoid printing passwords! """
    if original_parameters_string is None:
        return {}

    if isinstance(original_parameters_string, bytes):
        mystr = original_parameters_string.decode("utf-8")
    elif isinstance(original_parameters_string, str):
        mystr = original_parameters_string
    else:
        mystr = str(original_parameters_string)

    if mystr.strip() == '':
        return {}

    urlencoded = False
    try:
        parameters = json.loads(mystr)
    except json.decoder.JSONDecodeError:
        try:
            parameters = urllib.parse.parse_qs(mystr)
            urlencoded = True
        except BaseException:

            return original_parameters_string

    return obfuscate_dict(parameters, urlencoded=urlencoded)


def obfuscate_url(url):
    return re.sub(r'\/\/.*:.*@', '//***:***@', url)


def obfuscate_dict(parameters, urlencoded=False):

    if not isinstance(parameters, dict):
        return parameters

    output = {}
    for key, value in parameters.items():

        if key in OBSCURED_FIELDS:
            value = OBSCURE_VALUE
        elif isinstance(value, str):
            try:
                if len(value) > MAX_CHAR_LEN:
                    value = value[:MAX_CHAR_LEN] + "..."
            except IndexError:
                pass
        elif urlencoded and isinstance(value, list):
            # urllib.parse.parse_qs converts all elements in single-elements lists...
            # converting back to the original element
            if len(value) == 1:
                value = value[0]
        output[key] = value

    return output
