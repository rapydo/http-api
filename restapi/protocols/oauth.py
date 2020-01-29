# -*- coding: utf-8 -*-

"""
Oauth handling
"""

from flask_oauthlib.client import OAuth
from restapi.utilities.logs import log

####################################
# Oauth2
oauth = OAuth()
log.debug("Oauth2 object created")
