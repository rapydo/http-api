# -*- coding: utf-8 -*-

"""
Main server factory.
We create all the components here!
"""

from flask_cors import CORS
from utilities.logs import get_logger

log = get_logger(__name__)


# ####################################
# Allow cross-domain requests
# e.g. for JS and Upload

cors = CORS(
    allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
    supports_credentials=['true'],
    methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
log.verbose("Created CORS requests")

# # WARNING: in case 'cors' write too much, you could fix it like this
# import logging
# corslogger = logging.getLogger('.server.cors')
# corslogger.setLevel(logging.WARNING)
