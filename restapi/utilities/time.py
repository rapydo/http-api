from datetime import datetime

import dateutil.parser
import pytz


def date_from_string(date, fmt="%d/%m/%Y"):

    if not date:
        return ""

    try:
        return_date = datetime.strptime(date, fmt)
    except BaseException:
        return_date = dateutil.parser.parse(date)

    # TODO: test me with: 2017-09-22T07:10:35.822772835Z
    if return_date.tzinfo is None:
        return pytz.utc.localize(return_date)

    return return_date
