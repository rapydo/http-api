# -*- coding: utf-8 -*-

from datetime import datetime
import dateutil.parser
import pytz

from restapi.utilities.logs import log


def timestamp_from_string(timestamp_string):
    """
    Neomodels complains about UTC, this is to fix it.
    Taken from http://stackoverflow.com/a/21952077/2114395
    """

    precision = float(timestamp_string)
    # return datetime.fromtimestamp(precision)

    utc_dt = datetime.utcfromtimestamp(precision)
    aware_utc_dt = utc_dt.replace(tzinfo=pytz.utc)

    return aware_utc_dt


def date_from_string(date, fmt="%d/%m/%Y"):

    if date == "":
        return ""
    # datetime.now(pytz.utc)
    try:
        return_date = datetime.strptime(date, fmt)
    except BaseException:
        return_date = dateutil.parser.parse(date)

    # TODO: test me with: 2017-09-22T07:10:35.822772835Z
    if return_date.tzinfo is None:
        return pytz.utc.localize(return_date)

    return return_date


def string_from_timestamp(timestamp):
    if timestamp == "":
        return ""
    try:
        date = datetime.fromtimestamp(float(timestamp))
        return date.isoformat()
    except BaseException:
        log.warning("Errors parsing {}", timestamp)
        return ""
