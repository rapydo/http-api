# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import urllib
import logging
# import traceback
from contextlib import contextmanager
from logging.config import fileConfig

try:
    from json.decoder import JSONDecodeError
except ImportError:
    # fix for Python 3.4+
    JSONDecodeError = ValueError


#######################
# DEBUG level is 10 (https://docs.python.org/3/howto/logging.html)
CRITICAL_EXIT = 60
PRINT_STACK = 59
PRINT = 9
VERBOSE = 5
VERY_VERBOSE = 1
DEFAULT_LOGLEVEL_NAME = 'info'

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


def script_abspath(file, *suffixes):
    return os.path.join(os.path.dirname(os.path.realpath(file)), *suffixes)


AVOID_COLORS_ENV_LABEL = "IDONTWANTCOLORS"
LOG_INI_FILE = os.path.join(script_abspath(__file__), 'logging.ini')
LOG_INI_TESTS_FILE = os.path.join(script_abspath(__file__), 'logging_tests.ini')


#######################
@contextmanager
def suppress_stdout():
    """
    http://thesmithfam.org/blog/2012/10/25/
    temporarily-suppress-console-output-in-python/
    """
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout


#######################
def critical_exit(self, message=None, *args, **kws):

    error_code = kws.pop('error_code', 1)
    if not isinstance(error_code, int):
        raise ValueError("Error code must be an integer")
    if error_code < 1:
        raise ValueError("Cannot exit with value below 1")

    if self.isEnabledFor(CRITICAL_EXIT):
        if message is not None:
            # Yes, logger takes its '*args' as 'args'.
            self._log(  # pylint:disable=protected-access
                CRITICAL_EXIT, message, args, **kws
            )

    # TODO: check if raise is better
    sys.exit(error_code)


def fail_exit(self, message, *args, **kws):
    message = '(FAIL)\t%s' % message
    return self.error(message, *args, **kws)


# def print_stack(self, message, *args, **kws):
#     if self.isEnabledFor(PRINT_STACK):
#         print("")
#         self._log(PRINT_STACK, message, args, **kws)  # pylint:disable=protected-access
#         traceback.print_stack()
#         print("\n\n")


# def myprint(self, message, *args, **kws):
#     # if self.isEnabledFor(PRINT):
#     if self.isEnabledFor(logging.DEBUG):
#         message = "\033[33;5m%s" % message
#         print(message, *args, **kws)
#         print("\033[1;0m", end='')


def verbose(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(VERBOSE):
        self._log(VERBOSE, message, args, **kws)  # pylint:disable=protected-access


def very_verbose(self, message, *args, **kws):
    if self.isEnabledFor(VERY_VERBOSE):
        # Yes, logger takes its '*args' as 'args'.
        self._log(VERY_VERBOSE, message, args, **kws)  # pylint:disable=protected-access


# def beeprint_print(self, myobject, prefix_line=None):
#     """
#     Make object(s) and structure(s) clearer to debug
#     """

#     if prefix_line is not None:
#         print("PRETTY PRINT [%s]" % prefix_line)
#     from beeprint import pp

#     pp(myobject)
#     return self


# def prettyprinter_print(self, myobject, prefix_line=None):
#     """
#     Make object(s) and structure(s) clearer to debug
#     """

#     if prefix_line is not None:
#         print("PRETTY PRINT [%s]" % prefix_line)
#     from prettyprinter import pprint as pp

#     pp(myobject)
#     return self


def checked(self, message, *args, **kws):

    level = logging.INFO

    if self.isEnabledFor(level):
        # Yes, logger takes its '*args' as 'args'.
        # message = "\u2713 %s" % message

        if self.disable_unicode:
            message = "(CHECKED) %s" % message
        elif self.colors_enabled:
            message = "\033[0;32m\u2713\033[0m %s" % message
        else:
            message = "\u2713 %s" % message
        self._log(level, message, args, **kws)  # pylint:disable=protected-access


@staticmethod
def clear_screen():
    sys.stderr.write("\x1b[2J\x1b[H")


logging.addLevelName(CRITICAL_EXIT, "EXIT")
logging.Logger.critical_exit = critical_exit
logging.Logger.exit = critical_exit
# logging.Logger.fail = fail_exit
logging.CRITICAL_EXIT = CRITICAL_EXIT

# logging.addLevelName(PRINT_STACK, "PRINT_STACK")
# logging.Logger.print_stack = print_stack
# logging.PRINT_STACK = PRINT_STACK

# logging.addLevelName(PRINT, "PRINT")
# logging.Logger.print = myprint
# logging.PRINT = PRINT

logging.addLevelName(VERBOSE, "VERBOSE")
logging.Logger.verbose = verbose
logging.VERBOSE = VERBOSE

logging.addLevelName(VERY_VERBOSE, "VERY_VERBOSE")
logging.Logger.very_verbose = very_verbose
logging.VERY_VERBOSE = VERY_VERBOSE

# logging.Logger.pp = beeprint_print
# logging.Logger.app = prettyprinter_print
logging.Logger.checked = checked
logging.Logger.clear_screen = clear_screen


class LogMe(object):
    """ A common logger to be used all around development packages """

    def __init__(self):

        #####################
        self.log_level = None
        self.colors_enabled = True
        self.testing_mode = False
        self.disable_unicode = False
        super(LogMe, self).__init__()

        #####################
        if AVOID_COLORS_ENV_LABEL in os.environ:
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
        if self.testing_mode:
            fileConfig(LOG_INI_TESTS_FILE)
        else:
            fileConfig(LOG_INI_FILE)

        #####################
        # modify logging labels colors
        if self.colors_enabled:
            logging.addLevelName(
                logging.CRITICAL_EXIT,
                "\033[4;33;41m%s\033[1;0m"
                % logging.getLevelName(logging.CRITICAL_EXIT),
            )
            logging.addLevelName(
                logging.PRINT_STACK,
                "\033[5;37;41m%s\033[1;0m" % logging.getLevelName(logging.PRINT_STACK),
            )
            logging.addLevelName(
                logging.CRITICAL,
                "\033[5;37;41m%s\033[1;0m" % logging.getLevelName(logging.CRITICAL),
            )
            logging.addLevelName(
                logging.ERROR,
                "\033[4;37;41m%s\033[1;0m" % logging.getLevelName(logging.ERROR),
            )
            logging.addLevelName(
                logging.WARNING,
                "\033[1;30;43m%s\033[1;0m" % logging.getLevelName(logging.WARNING),
            )
            logging.addLevelName(
                logging.INFO,
                "\033[1;32;49m%s\033[1;0m" % logging.getLevelName(logging.INFO),
            )
            logging.addLevelName(
                logging.DEBUG,
                "\033[7;30;46m%s\033[1;0m" % logging.getLevelName(logging.DEBUG),
            )
            logging.addLevelName(
                logging.VERBOSE,
                "\033[1;90;49m%s\033[1;0m" % logging.getLevelName(logging.VERBOSE),
            )
            logging.addLevelName(
                logging.VERY_VERBOSE,
                "\033[7;30;47m%s\033[1;0m" % logging.getLevelName(logging.VERY_VERBOSE),
            )

    def set_debug(self, debug=True, level=None):
        # print("DEBUG IS", debug)
        # if debug is None:
        #     return

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
        """ Recover the right logger + set a proper specific level """
        if self.colors_enabled:
            name = "\033[1;90m%s\033[1;0m" % name
        logger = logging.getLogger(name)

        if verbosity is not None:
            self.set_debug(True, verbosity)
        #     logger.warning("TRAVIS: %s/%s", verbosity, self.log_level)
        # else:
        #     logger.warning("TRAVIS not: %s/%s", verbosity, self.log_level)

        # print("LOGGER LEVEL", self.log_level, logging.INFO)
        logger.setLevel(self.log_level)
        logger.colors_enabled = self.colors_enabled
        logger.disable_unicode = self.disable_unicode
        return logger


def set_global_log_level(package=None, app_level=None):

    # external_level = logging.WARNING
    external_level = logging.ERROR
    if app_level is None:
        app_level = please_logme.log_level

    # List of rapydo packages to include into the current level of debugging
    internal_packages = [
        'utilities',
        # 'develop',
        'controller',
        'restapi',
    ]

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
            # print("placeholder", key, value)
            continue

        key_colors = key.split('0m')
        if len(key_colors) > 1:
            key = key_colors[1]
        key_base = key.split('.')[0]

        if package is not None and package + '.' in key:
            # print("current", key, value.level)
            value.setLevel(app_level)
        elif key_base == package_base:
            # print("current package", key, key_base)
            value.setLevel(app_level)
        elif __package__ + '.' in key or 'flask_ext' in key:
            # print("common", key)
            value.setLevel(app_level)
        elif key in internal_packages:
            value.setLevel(app_level)
        elif key == 'test_logs':
            # print("internal", key, package)
            value.setLevel(app_level)
        else:
            value.setLevel(external_level)


please_logme = LogMe()
# log = please_logme.get_new_logger(__name__)


def get_logger(name):
    """ Recover the right logger + set a proper specific level """

    # read from os DEBUG_LEVEL (level of verbosity)
    # configurated on a container level
    USER_DEBUG_LEVEL = os.environ.get('DEBUG_LEVEL', 'VERY_VERBOSE')
    VERBOSITY_REQUESTED = getattr(logging, USER_DEBUG_LEVEL.upper())

    return please_logme.get_new_logger(name, verbosity=VERBOSITY_REQUESTED)


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
    except JSONDecodeError:

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
