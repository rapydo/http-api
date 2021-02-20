from datetime import datetime, timedelta, tzinfo
from typing import Literal, Optional

import pytz

from restapi.exceptions import BadRequest

EPOCH: datetime = datetime.fromtimestamp(0, pytz.utc)

AllowedTimedeltaPeriods = Literal[
    "days", "seconds", "microseconds", "milliseconds", "minutes", "hours", "weeks"
]


def get_now(tz: Optional[tzinfo]) -> datetime:

    if tz is None:
        # Create a offset-naive datetime
        return datetime.now()

    # Create a offset-aware datetime
    return datetime.now(pytz.utc)


def date_lower_than(a: datetime, b: datetime) -> bool:
    return a.replace(tzinfo=pytz.utc) < b.replace(tzinfo=pytz.utc)


def get_timedelta(every: int, period: AllowedTimedeltaPeriods) -> timedelta:

    if period == "seconds":
        return timedelta(seconds=every)

    if period == "days":
        return timedelta(days=every)

    if period == "microseconds":
        return timedelta(microseconds=every)

    if period == "milliseconds":
        return timedelta(milliseconds=every)

    if period == "minutes":
        return timedelta(minutes=every)

    if period == "hours":
        return timedelta(hours=every)

    if period == "weeks":
        return timedelta(weeks=every)

    raise BadRequest(f"Invalid timedelta period: {period}")
