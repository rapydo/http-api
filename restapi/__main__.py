#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""

RESTful API Python 3 Flask server

"""

import os
import better_exceptions as be
from restapi.confs import PRODUCTION
from restapi.server import create_app
from utilities.logs import get_logger

log = get_logger(__name__)

# Connection internal to containers, proxy handle all HTTPS calls
# We may safely disable HTTPS on OAUTHLIB requests
if PRODUCTION:
    # http://stackoverflow.com/a/27785830/2114395
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

#############################
# BE FLASK
app = create_app(name='REST_API')

if __name__ == "__main__":
    log.debug("Server running (w/ %s)", be.__name__)
    app.run(host='0.0.0.0', threaded=True)
