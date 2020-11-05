import sys

from restapi.utilities.logs import log


def print_and_exit(message, *args, **kwargs):
    log.critical(message, *args, **kwargs)
    sys.exit(1)
