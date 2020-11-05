import sys


def print_and_exit(message, *args, **kwargs):
    # Do not import outside the function to prevent circular imports
    from restapi.utilities.logs import log

    log.critical(message, *args, **kwargs)
    sys.exit(1)
