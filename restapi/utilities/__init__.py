import sys
from typing import NoReturn, Optional


def print_and_exit(
    message: str, *args: Optional[str], **kwargs: Optional[str]
) -> NoReturn:
    # Do not import outside the function to prevent circular imports
    from restapi.utilities.logs import log

    log.critical(message, *args, **kwargs)
    sys.exit(1)
