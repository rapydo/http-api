# -*- coding: utf-8 -*-

"""
Take care of authenticatin with External Service with Oauth2 protocol.

Testend against GitHub, then worked off B2ACCESS (EUDAT oauth service)
"""

import os
from base64 import b64encode
from rapydo.protocols.oauth import oauth
from rapydo.confs import PRODUCTION, CUSTOM_PACKAGE
from rapydo.utils.globals import mem
from rapydo.utils.meta import Meta
from rapydo.utils.logs import get_logger

log = get_logger(__name__)

B2ACCESS_DEV_BASEURL = "https://unity.eudat-aai.fz-juelich.de"
B2ACCESS_DEV_URL = B2ACCESS_DEV_BASEURL + ":8443"
B2ACCESS_DEV_CA_URL = B2ACCESS_DEV_BASEURL + ":8445"

B2ACCESS_PROD_BASEURL = "https://b2access.eudat.eu"
B2ACCESS_PROD_URL = B2ACCESS_PROD_BASEURL + ":8443"
B2ACCESS_PROD_CA_URL = B2ACCESS_PROD_BASEURL + ":8445"

meta = Meta()
module = meta.get_module_from_string(
    "%s.%s.%s" % (CUSTOM_PACKAGE, 'apis', 'common')
)

# TO BE FIXED
if module is None:
    B2ACCESS_ENV = PRODUCTION
else:
    B2ACCESS_ENV = getattr(module, 'CURRENT_B2ACCESS_ENVIRONMENT', 'unknown')
B2ACCESS_ENV_PRODUCTION = B2ACCESS_ENV == 'production'


class ExternalLogins(object):

    _available_services = {}

    # TOFIX: FROM MATTIA: the testing parameter is still required?
    def __init__(self, testing=False):

        # TOFIX: FROM MATTIA: removed this if
        # if testing:
        #     log.warning("currently skipping oauth2 in tests")
        #     # TOFIX: provide some tests for oauth2 calls
        #     return

        # Global memory of oauth2 services across the whole server instance:
        # because we may define the external service
        # in different places of the code
        if not self._check_if_services_exist():
            # Note: this gets called only at INIT time
            # TOFIX: FROM MATTIA: the testing parameter is still required?
            mem.oauth2_services = self.get_oauth2_instances(testing)

        # Recover services for current instance
        # This list will be used from the outside world
        self._available_services = mem.oauth2_services

    @staticmethod
    def _check_if_services_exist():
        return getattr(mem, 'oauth2_services', None) is not None

    # TOFIX: FROM MATTIA: the testing parameter is still required?
    def get_oauth2_instances(self, testing=False):
        """
        Setup every oauth2 instance available through configuration
        """

        services = {}

        # For each defined internal service
        for key, func in meta.get_methods_inside_instance(self).items():

            # log.info("META %s-%s" % (key, func))

            # Check if credentials are enabled inside docker env
            var1 = key.upper() + '_APPNAME'
            var2 = key.upper() + '_APPKEY'

            if var1 not in os.environ or var2 not in os.environ:
                log.verbose("Skipping Oauth2 service %s" % key)
                continue

            # Call the service and save it
            try:
                # TOFIX: FROM MATTIA: the testing parameter is still required?
                obj = func(testing)

                # Make sure it's always a dictionary of objects
                if not isinstance(obj, dict):
                    obj = {key: obj}

                # Cycle all the Oauth2 group services
                for name, oauth2 in obj.items():
                    services[name] = oauth2
                    log.debug("Created Oauth2 service %s" % name)

            except Exception as e:
                log.critical(
                    "Could not request oauth2 service %s:\n%s" % (key, e))

        return services

    def github(self):
        """ This APIs are very useful for testing purpose """

        return oauth.remote_app(
            'github',
            consumer_key=os.environ.get('GITHUB_APPNAME', 'yourappusername'),
            consumer_secret=os.environ.get('GITHUB_APPKEY', 'yourapppw'),
            base_url='https://github.com/login/oauth',
            request_token_params={'scope': 'user'},
            request_token_url=None,
            access_token_method='POST',
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize'
        )

    # TOFIX: FROM MATTIA: the testing parameter is still required?
    def b2access(self, testing=False):

        # LOAD CREDENTIALS FROM DOCKER ENVIRONMENT
        key = os.environ.get('B2ACCESS_APPNAME', 'yourappusername')
        secret = os.environ.get('B2ACCESS_APPKEY', 'yourapppw')

        # SET OTHER URLS
        token_url = B2ACCESS_DEV_URL + '/oauth2/token'
        authorize_url = B2ACCESS_DEV_URL + '/oauth2-as/oauth2-authz'

        if B2ACCESS_ENV_PRODUCTION:
            token_url = B2ACCESS_PROD_URL + '/oauth2/token'
            authorize_url = B2ACCESS_PROD_URL + '/oauth2-as/oauth2-authz'

        # COMMON ARGUMENTS
        arguments = {
            'consumer_key': key,
            'consumer_secret': secret,
            'access_token_url': token_url,
            'authorize_url': authorize_url,
            'request_token_params':
                {'scope': ['USER_PROFILE', 'GENERATE_USER_CERTIFICATE']},
            'request_token_url': None,
            'access_token_method': 'POST'
        }

        #####################
        # B2ACCESS
        arguments['base_url'] = B2ACCESS_DEV_URL + '/oauth2/'
        if B2ACCESS_ENV_PRODUCTION:
            arguments['base_url'] = B2ACCESS_PROD_URL + '/oauth2/'

        b2access_oauth = oauth.remote_app('b2access', **arguments)

        #####################
        # B2ACCESS CERTIFICATION AUTHORITY
        arguments['base_url'] = B2ACCESS_DEV_CA_URL
        if B2ACCESS_ENV_PRODUCTION:
            arguments['base_url'] = B2ACCESS_PROD_CA_URL

        b2accessCA = oauth.remote_app('b2accessCA', **arguments)

        #####################
        # Decorated session save of the token
        @b2access_oauth.tokengetter
        @b2accessCA.tokengetter
        def get_b2access_oauth_token():
            from flask import session
            return session.get('b2access_token')

        return {
            'b2access': b2access_oauth,
            'b2accessCA': b2accessCA,
            'prod': B2ACCESS_ENV_PRODUCTION
        }


def decorate_http_request(remote):
    """
    Necessary for B2ACCESS oauth2 servers.

    Decorate the OAuth call
    to access token endpoint
    to inject the Authorization header.

    Original source (for Python2) by @akrause2014:
    https://github.com/akrause2014
        /eudat/blob/master/oauth2-client/b2access_client.py
    """

    old_http_request = remote.http_request
    # print("old http request", old_http_request)

    def new_http_request(uri, headers=None, data=None, method=None):
        response = None
        if not headers:
            headers = {}
        if not headers.get("Authorization"):
            client_id = remote.consumer_key
            client_secret = remote.consumer_secret
            userpass = b64encode(
                str.encode("%s:%s" % (client_id, client_secret))
            ).decode("ascii")
            headers.update({'Authorization': 'Basic %s' % (userpass,)})
        response = old_http_request(
            uri, headers=headers, data=data, method=method)

        # TODO: check if we may handle failed B2ACCESS response here
        return response

    remote.http_request = new_http_request
