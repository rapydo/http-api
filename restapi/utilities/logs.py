import json
import os
import re
import sys
import urllib.parse
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from loguru import logger as log

from restapi.config import PRODUCTION, TESTING
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


LOGS_PATH: Optional[str] = os.path.join(LOGS_FOLDER, f"{LOGS_FILE}.log")
EVENTS_PATH: Optional[str] = os.path.join(LOGS_FOLDER, "security-events.log")


class Events(str, Enum):
    access = "access"
    create = "create"
    modify = "modify"
    delete = "delete"
    login = "login"
    logout = "logout"
    failed_login = "failed_login"
    refused_login = "refused_login"
    activation = "activation"
    change_password = "change_password"
    reset_password_request = "reset_password_request"


log.level("VERBOSE", no=1, color="<fg #666>")
log.level("INFO", color="<green>")
log.level("EVENT", no=0)

log.remove()


# Prevent exceptions on standard sink
def print_message_on_stderr(record):
    return record.get("exception") is None


if LOGS_PATH is not None:
    FILE_LOGLEVEL = "WARNING" if not TESTING else "INFO"
    try:
        log.add(
            LOGS_PATH,
            level=FILE_LOGLEVEL,
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

        fmt = ""
        fmt += "{time:YYYY-MM-DD HH:mm:ss,SSS} "
        fmt += "{extra[ip]} "
        fmt += "{extra[user]} "
        fmt += "{extra[event]} "
        fmt += "{extra[target_type]} "
        fmt += "{extra[target_id]} "
        fmt += "{extra[payload]} "
        log.add(
            EVENTS_PATH,
            level=0,
            rotation="1 month",
            filter=lambda record: "event" in record["extra"],
            format=fmt,
            # Otherwise in case of missing extra fields the event will be simply ignored
            catch=False,
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
        log_id = getattr(set_logger, "log_id")
        log.remove(log_id)

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

    setattr(set_logger, "log_id", log_id)


set_logger(log_level)

# Logs utilities

# Can't understand why mypy is unable to understand Env.get_int, since it is annotated
# with `-> int` .. but mypy raises:
# Cannot determine type of 'get_int'
# mypy: ignore-errors
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
    "totp",
    "totp_code",
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


def obfuscate_url(url: str) -> str:
    return re.sub(r"\/\/.*:.*@", "//***:***@", url)


def obfuscate_dict(parameters, urlencoded: bool = False, max_len=MAX_CHAR_LEN):

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
                if len(value) > max_len:
                    value = value[:max_len] + "..."
            except IndexError:
                pass

        output[key] = value

    return output


def parse_event_target(target: Any) -> Tuple[str, str]:
    if not target:
        return "", ""

    target_type = type(target).__name__

    if hasattr(target, "uuid"):
        return target_type, getattr(target, "uuid")

    if hasattr(target, "id"):
        return target_type, getattr(target, "id")

    return target_type, ""


# Save a log entry in security-events.log
def save_event_log(
    event: Events,
    target: Optional[Any] = None,
    payload: Optional[Dict[str, Any]] = None,
    user: Optional[Any] = None,
    ip: str = "-",
) -> None:

    target_type, target_id = parse_event_target(target)

    if payload:
        p = json.dumps(obfuscate_dict(payload, max_len=999))
    else:
        p = ""

    log.log(
        "EVENT",
        "",
        event=event,
        ip=ip,
        user=user.email if user else "-",
        target_id=target_id,
        target_type=target_type,
        payload=p,
    )
