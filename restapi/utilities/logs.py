# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import urllib
# import logging
from loguru import logger as log

LOGS_FOLDER = "/logs"
LOGS_FILE = os.environ.get("HOSTNAME", "backend")
LOGS_PATH = os.path.join(LOGS_FOLDER, "{}.log".format(LOGS_FILE))

log.level("VERBOSE", no=1, color="<fg #666>")
log.level("INFO", color="<green>")


def change_formatting_syntax(message):

    # Deprecated since 0.7.1
    if "%s" in message:
        log.original_warning(
            "Deprecated %s in log message ({}), replace it with {}", message, '{}')
    elif "%d" in message:
        log.original_warning(
            "Deprecated %d in log message ({}), replace it with {}", message, '{}')
    elif "%f" in message:
        log.original_warning(
            "Deprecated %f in log message ({}), replace it with {}", message, '{}')
    elif "%" in message:
        log.original_warning(
            "Found a % in log message ({}), please verify if correctly used", message)
    return message


def get_logger(not_used):
    # Deprecated since 0.7.1
    log.warning("Deprecated get_logger, import log instead")
    return log


def verbose(message="", *args, **kwargs):
    message = change_formatting_syntax(message)
    log.log("VERBOSE", message, *args, **kwargs)


def exit(message="", *args, **kwargs):
    args[0] = change_formatting_syntax(args[0])
    error_code = kwargs.pop('error_code', 1)
    if not isinstance(error_code, int):
        raise ValueError("Error code must be an integer")
    if error_code < 1:
        raise ValueError("Cannot exit with value below 1")

    log.critical(message, *args, **kwargs)
    sys.exit(error_code)


log.original_debug = log.debug
log.original_info = log.info
log.original_warning = log.warning
log.original_error = log.error


def tmp_debug(message="", *args, **kwargs):
    message = change_formatting_syntax(message)
    log.original_debug(message, *args, **kwargs)


def tmp_info(message="", *args, **kwargs):
    message = change_formatting_syntax(message)
    log.original_info(message, args, **kwargs)


def tmp_warning(message="", *args, **kwargs):
    message = change_formatting_syntax(message)
    log.original_warning(message, args, **kwargs)


def tmp_error(message="", *args, **kwargs):
    message = change_formatting_syntax(message)
    log.original_error(message, *args, **kwargs)


log.debug = tmp_debug
log.info = tmp_info
log.warning = tmp_warning
log.error = tmp_error

log.verbose = verbose
log.exit = exit

log.remove()
if LOGS_PATH is not None:
    log.add(LOGS_PATH, level="WARNING", rotation="1 week", retention="4 weeks")

log.add(sys.stderr, colorize=True, format="<fg #FFF>{time:YYYY-MM-DD HH:mm:ss,SSS}</fg #FFF> [<level>{level}</level> <fg #666>{name}:{line}</fg #666>] <fg #FFF>{message}</fg #FFF>")

"""
# DEBUG level is 10 (https://docs.python.org/3/howto/logging.html)
EXIT = 60
VERBOSE = 5


def exit(self, message=None, *args, **kws):

    error_code = kws.pop('error_code', 1)
    if not isinstance(error_code, int):
        raise ValueError("Error code must be an integer")
    if error_code < 1:
        raise ValueError("Cannot exit with value below 1")

    if self.isEnabledFor(EXIT):
        if message is not None:
            # Yes, logger takes its '*args' as 'args'.
            self._log(  # pylint:disable=protected-access
                EXIT, message, args, **kws
            )

    # TODO: check if raise is better
    sys.exit(error_code)


def verbose(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(VERBOSE):
        self._log(VERBOSE, message, args, **kws)  # pylint:disable=protected-access


logging.addLevelName(EXIT, "EXIT")
logging.Logger.exit = exit
logging.EXIT = EXIT

logging.addLevelName(VERBOSE, "VERBOSE")
logging.Logger.verbose = verbose
logging.VERBOSE = VERBOSE


class LogMe(object):
    # A common logger to be used all around development packages

    def __init__(self):

        #####################
        self.log_level = None
        self.colors_enabled = True
        self.testing_mode = False
        self.disable_unicode = False
        super(LogMe, self).__init__()

        #####################
        if "IDONTWANTCOLORS" in os.environ:
            self.colors_enabled = False
        testing_key = "TESTING"
        if testing_key in os.environ and os.environ.get(testing_key) == '1':
            self.testing_mode = True
            self.colors_enabled = False
        if "DISABLE_UNICODE" in os.environ:
            self.disable_unicode = True

        #####################
        # Set default logging handler to avoid "No handler found" warnings.
        try:  # Python 2.7+
            from logging import NullHandler
        except ImportError:

            class NullHandler(logging.Handler):
                def emit(self, record):
                    pass

        #####################
        # Make sure there is at least one logger
        logging.getLogger(__name__).addHandler(NullHandler())

        # Format
        def script_abspath(file, *suffixes):
            return os.path.join(os.path.dirname(os.path.realpath(file)), *suffixes)

        from logging.config import fileConfig
        if self.testing_mode:
            LOG_INI_TESTS_FILE = os.path.join(
                script_abspath(__file__), 'logging_tests.ini')
            fileConfig(LOG_INI_TESTS_FILE)
        else:
            LOG_INI_FILE = os.path.join(
                script_abspath(__file__), 'logging.ini')
            fileConfig(LOG_INI_FILE)

        #####################
        # modify logging labels colors
        if self.colors_enabled:
            logging.addLevelName(
                logging.EXIT,
                "\033[4;33;41m{}\033[1;0m".format(
                    logging.getLevelName(logging.EXIT)),
            )
            logging.addLevelName(
                logging.CRITICAL,
                "\033[5;37;41m{}\033[1;0m".format(
                    logging.getLevelName(logging.CRITICAL)),
            )
            logging.addLevelName(
                logging.ERROR,
                "\033[4;37;41m{}\033[1;0m".format(
                    logging.getLevelName(logging.ERROR)),
            )
            logging.addLevelName(
                logging.WARNING,
                "\033[1;30;43m{}\033[1;0m".format(
                    logging.getLevelName(logging.WARNING)),
            )
            logging.addLevelName(
                logging.INFO,
                "\033[1;32;49m{}\033[1;0m".format(
                    logging.getLevelName(logging.INFO)),
            )
            logging.addLevelName(
                logging.DEBUG,
                "\033[7;30;46m{}\033[1;0m".format(
                    logging.getLevelName(logging.DEBUG)),
            )
            logging.addLevelName(
                logging.VERBOSE,
                "\033[1;90;49m{}\033[1;0m".format(
                    logging.getLevelName(logging.VERBOSE)),
            )

    def set_debug(self, debug=True, level=None):

        self.debug = debug
        if self.debug:
            if level is not None:
                self.log_level = level
            else:
                self.log_level = logging.DEBUG
        else:
            self.log_level = logging.INFO

        return self.log_level

    def get_new_logger(self, name, verbosity=None):
        # Recover the right logger + set a proper specific level
        if self.colors_enabled:
            name = "\033[1;90m{}\033[1;0m".format(name)
        logger = logging.getLogger(name)

        if verbosity is not None:
            self.set_debug(True, verbosity)

        logger.setLevel(self.log_level)
        logger.colors_enabled = self.colors_enabled
        logger.disable_unicode = self.disable_unicode
        return logger


def set_global_log_level(package=None, app_level=None):

    # external_level = logging.WARNING
    external_level = logging.ERROR
    if app_level is None:
        app_level = please_logme.log_level

    # A list of packages that make too much noise inside the logs
    external_packages = [
        logging.getLogger('requests'),
        logging.getLogger('werkzeug'),
        logging.getLogger('plumbum'),
        logging.getLogger('neo4j'),
        logging.getLogger('neomodel'),
        logging.getLogger('neobolt'),
        logging.getLogger('httpstream'),
        logging.getLogger('amqp'),
        logging.getLogger('schedule'),
        logging.getLogger('googleapiclient'),
        logging.getLogger('oauth2client'),
        logging.getLogger('mailchimp3'),
    ]

    for logger in external_packages:
        logger.setLevel(external_level)

    for handler in logging.getLogger().handlers:
        handler.setLevel(app_level)

    logging.getLogger().setLevel(app_level)
    package_base = package.split('.')[0]

    for key, value in logging.Logger.manager.loggerDict.items():

        if not isinstance(value, logging.Logger):
            continue

        key_colors = key.split('0m')
        if len(key_colors) > 1:
            key = key_colors[1]
        key_base = key.split('.')[0]

        if package is not None and package + '.' in key:
            value.setLevel(app_level)
        elif key_base == package_base:
            value.setLevel(app_level)
        elif __package__ + '.' in key or 'flask_ext' in key:
            value.setLevel(app_level)
        elif key == 'restapi':
            value.setLevel(app_level)
        elif key == 'test_logs':
            value.setLevel(app_level)
        else:
            value.setLevel(external_level)


please_logme = LogMe()


def get_logger(name):
    # Recover the right logger + set a proper specific level

    # read from os DEBUG_LEVEL (level of verbosity)
    # configurated on a container level
    USER_DEBUG_LEVEL = os.environ.get('DEBUG_LEVEL', 'VERBOSE')
    VERBOSITY_REQUESTED = getattr(logging, USER_DEBUG_LEVEL.upper())

    return please_logme.get_new_logger(name, verbosity=VERBOSITY_REQUESTED)

"""
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


def re_obscure_pattern(string):

    patterns = {'http_credentials': r'[^:]+\:([^@:]+)\@[^:]+:[^:]'}

    for _, pattern in patterns.items():
        p = re.compile(pattern)
        m = p.search(string)
        if m:
            g = m.group(1)
            string = string.replace(g, OBSCURE_VALUE)

    return string


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
