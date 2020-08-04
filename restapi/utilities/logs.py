import json
import os
import re
import sys
import urllib

from loguru import logger as log

from restapi.confs import PRODUCTION
from restapi.env import Env

log_level = os.getenv("LOGURU_LEVEL", "DEBUG")
LOGS_FOLDER = "/logs"
HOSTNAME = os.getenv("HOSTNAME", "backend")
CONTAINER_ID = os.getenv("CONTAINER_ID", "")
IS_CELERY_CONTAINER = os.getenv("IS_CELERY_CONTAINER", "0")

# BACKEND-SERVER
if IS_CELERY_CONTAINER == "0":
    LOGS_FILE = HOSTNAME
# Flower or Celery-Beat
elif HOSTNAME != CONTAINER_ID:  # pragma: no cover
    LOGS_FILE = HOSTNAME
    LOGS_FOLDER = os.path.join(LOGS_FOLDER, "celery")
    if not os.path.isdir(LOGS_FOLDER):
        os.makedirs(LOGS_FOLDER, exist_ok=True)
# Celery (variables name due to scaling)
else:  # pragma: no cover
    LOGS_FILE = f"celery_{HOSTNAME}"
    LOGS_FOLDER = os.path.join(LOGS_FOLDER, "celery")
    if not os.path.isdir(LOGS_FOLDER):
        os.makedirs(LOGS_FOLDER, exist_ok=True)


LOGS_PATH = os.path.join(LOGS_FOLDER, f"{LOGS_FILE}.log")

log.level("VERBOSE", no=1, color="<fg #666>")
log.level("INFO", color="<green>")


def verbose(*args, **kwargs):
    log.log("VERBOSE", *args, **kwargs)


def critical_exit(message="", *args, **kwargs):
    log.critical(message, *args, **kwargs)
    sys.exit(1)


log.verbose = verbose
log.exit = critical_exit

log.remove()


# Prevent exceptions on standard sink
def print_message_on_stderr(record):
    return record.get("exception") is None


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
    except PermissionError as p:  # pragma: no cover
        log.error(p)
        LOGS_PATH = None


fmt = ""
fmt += "<fg #FFF>{time:YYYY-MM-DD HH:mm:ss,SSS}</fg #FFF> "
fmt += "[<level>{level}</level> "
fmt += "<fg #666>{name}:{line}</fg #666>] "
fmt += "<fg #FFF>{message}</fg #FFF>"


# Set the default logger with the given log level and save the log_id as static variable
# Further call to this function will remove the previous logger (based on saved log_id)
def set_logger(level):

    if hasattr(set_logger, "log_id"):
        log.remove(set_logger.log_id)

    log_id = log.add(
        sys.stderr,
        level=level,
        colorize=True,
        format=fmt,
        # If True the exception trace is extended upward, beyond the catching point
        # to show the full stacktrace which generated the error.
        backtrace=False,
        # Display variables values in exception trace to eases the debugging.
        # Disabled in production to avoid leaking sensitive data.
        # Note: enabled in development mode on the File Logger
        diagnose=False,
        filter=print_message_on_stderr,
    )

    set_logger.log_id = log_id


set_logger(log_level)

# Logs utilities

MAX_CHAR_LEN = Env.get_int("MAX_LOGS_LENGTH", 200)
OBSCURE_VALUE = "****"
OBSCURED_FIELDS = [
    "password",
    "pwd",
    "token",
    "access_token",
    "file",
    "filename",
    "new_password",
    "password_confirm",
]


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

    if mystr.strip() == "":
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
    return re.sub(r"\/\/.*:.*@", "//***:***@", url)


def obfuscate_dict(parameters, urlencoded=False):

    if not isinstance(parameters, dict):
        return parameters

    output = {}
    for key, value in parameters.items():

        if key in OBSCURED_FIELDS:
            value = OBSCURE_VALUE
        elif urlencoded and isinstance(value, list):
            # urllib.parse.parse_qs converts all elements in single-elements lists...
            # converting back to the original element
            if len(value) == 1:
                value = value[0]
        else:
            value = str(value)
            try:
                if len(value) > MAX_CHAR_LEN:
                    value = value[:MAX_CHAR_LEN] + "..."
            except IndexError:
                pass

        output[key] = value

    return output
