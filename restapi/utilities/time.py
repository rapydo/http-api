from datetime import datetime, tzinfo
from typing import Optional

import pytz

EPOCH: datetime = datetime.fromtimestamp(0, pytz.utc)


def get_now(tzinfo: Optional[tzinfo]) -> datetime:

    if tzinfo is None:
        # Create a offset-naive datetime
        return datetime.now()

    # Create a offset-aware datetime
    return datetime.now(pytz.utc)
