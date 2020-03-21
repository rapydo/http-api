#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""

RESTful API Python 3 Flask server

"""

import os
import pretty_errors
from restapi.confs import PRODUCTION
from restapi.server import create_app
from restapi.utilities.logs import log

# Connection internal to containers, proxy handle all HTTPS calls
# We may safely disable HTTPS on OAUTHLIB requests
if PRODUCTION:
    # http://stackoverflow.com/a/27785830/2114395
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
BIND_INTERFACE = "0.0.0.0"

#############################
# BE FLASK
app = create_app(name='REST_API')

if __name__ == "__main__":
    log.debug("Server running (w/ {})", pretty_errors.__name__)
    app.run(host=BIND_INTERFACE, threaded=True)
