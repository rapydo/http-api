from datetime import datetime

import pytz

EPOCH = datetime.fromtimestamp(0, pytz.utc)


def get_now(tzinfo):

    if tzinfo is None:
        # Create a offset-naive datetime
        return datetime.now()

    # Create a offset-aware datetime
    return datetime.now(pytz.utc)
