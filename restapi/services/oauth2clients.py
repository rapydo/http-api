# -*- coding: utf-8 -*-

"""
Take care of authenticatin with External Service with Oauth2 protocol.

Testend against GitHub, then worked off B2ACCESS (EUDAT oauth service)
"""

import os
from base64 import b64encode
from authlib.integrations.flask_client import OAuth
from restapi.utilities.globals import mem
from restapi.utilities.meta import Meta

from restapi.utilities.logs import log

meta = Meta()

B2ACCESS_MAIN_PORT = 8443
B2ACCESS_CA_PORT = 8445
B2ACCESS_URLS = {
    'development': 'unity.eudat-aai.fz-juelich.de',
    'staging': 'b2access-integration.fz-juelich.de',
    'production': 'b2access.eudat.eu',
}


def fetch_token(name, request):
    # if name in OAUTH1_SERVICES:
    #     model = OAuth1Token
    # else:
    #     model = OAuth2Token

    # token = model.find(
    #     name=name,
    #     user=request.user
    # )
    # return token.to_token()

    log.critical("fetch_token {} {}", name, request)
    return None


def save_request_token(name, request):
    log.critical("save_request_token {} {}", name, request)


def fetch_request_token(name, request):
    log.critical("fetch_request_token {} {}", name, request)


class ExternalLogins(object):

    _available_services = {}

    def __init__(self, app):

        self.oauth = OAuth(
            fetch_token=fetch_token
            # save_request_token=save_request_token,
            # fetch_request_token=fetch_request_token
        )
        self.oauth.init_app(app)
        log.info(self.oauth)
        # Global memory of oauth2 services across the whole server instance:
        # because we may define the external service
        # in different places of the code
        if not self._check_if_services_exist():
            # NOTE: this gets called only at INIT time
            mem.oauth2_services = self.get_oauth2_instances()

        # Recover services for current instance
        # This list will be used from the outside world
        self._available_services = mem.oauth2_services

    @staticmethod
    def _check_if_services_exist():
        return getattr(mem, 'oauth2_services', None) is not None

    def get_oauth2_instances(self):
        """
        Setup every oauth2 instance available through configuration
        """

        services = {}

        # For each defined internal service
        for key, func in meta.get_methods_inside_instance(self).items():

            # Check if credentials are enabled inside docker env
            var1 = key.upper() + '_APPNAME'
            var2 = key.upper() + '_APPKEY'

            if var1 not in os.environ or var2 not in os.environ:
                log.verbose("Skipping Oauth2 service {}", key)
                continue

            # Call the service and save it
            try:
                obj = func()

                # Make sure it's always a dictionary of objects
                if not isinstance(obj, dict):
                    obj = {key: obj}

                # Cycle all the Oauth2 group services
                for name, oauth2 in obj.items():
                    if oauth2 is None:
                        log.debug("Skipping failing credentials: {}", key)
                    else:
                        services[name] = oauth2
                        log.debug("Created Oauth2 service {}", name)

            except Exception as e:
                log.critical("Unable to request oauth2 service {}\n{}", key, e)

        return services

    def github(self):
        """ This APIs are very useful for testing purpose """

        return self.oauth.register(
            'github',
            client_id=os.environ.get('GITHUB_APPNAME', 'yourappusername'),
            client_secret=os.environ.get('GITHUB_APPKEY', 'yourapppw'),
            api_base_url='https://github.com/login/oauth',
            request_token_params={'scope': 'user'},
            request_token_url=None,
            access_token_method='POST',
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize',
        )

    def b2access(self):

        from restapi.services.detect import Detector as detect

        b2access_vars = detect.load_variables({'prefix': 'b2access'})
        selected_b2access = b2access_vars.get('env')
        if selected_b2access is None:
            return {}

        # load credentials from environment
        key = b2access_vars.get('appname', 'yourappusername')
        secret = b2access_vars.get('appkey', 'yourapppw')

        if secret is None or secret.strip() == '':
            log.warning("B2ACCESS credentials not set")
            return None

        api_base_url = B2ACCESS_URLS.get(selected_b2access)
        b2access_url = "https://{}:{}".format(api_base_url, B2ACCESS_MAIN_PORT)
        b2access_ca = "https://{}:{}".format(api_base_url, B2ACCESS_CA_PORT)

        # SET OTHER URLS
        token_url = b2access_url + '/oauth2/token'
        authorize_url = b2access_url + '/oauth2-as/oauth2-authz'

        # COMMON ARGUMENTS
        arguments = {
            'client_id': key,
            'client_secret': secret,
            'access_token_url': token_url,
            'authorize_url': authorize_url,
            'request_token_params': {
                'scope': ['USER_PROFILE', 'GENERATE_USER_CERTIFICATE']
            },
            # request_token_url is for oauth1
            'request_token_url': None,
            'access_token_method': 'POST',
        }

        # B2ACCESS main app
        arguments['api_base_url'] = b2access_url + '/oauth2/'
        b2access_oauth = self.oauth.register('b2access', **arguments)

        # B2ACCESS certification authority app
        arguments['api_base_url'] = b2access_ca
        b2accessCA = self.oauth.register('b2accessCA', **arguments)

        #####################
        # Decorated session save of the token
        # @b2access_oauth.tokengetter
        # @b2accessCA.tokengetter
        # def get_b2access_oauth_token():
        #     from flask import session

        #     return session.get('b2access_token')

        return {
            'b2access': b2access_oauth,
            'b2accessCA': b2accessCA,
            'prod': selected_b2access == 'production',
        }


def decorate_http_request(remote):
    """
    Decorate the OAuth call to access token endpoint,
    injecting the Authorization header.
    """

    old_http_request = remote.http_request

    def new_http_request(uri, headers=None, data=None, method=None):
        response = None
        if not headers:
            headers = {}
        if not headers.get("Authorization"):
            client_id = remote.client_id
            client_secret = remote.client_secret
            userpass = b64encode(
                str.encode("{}:{}".format(client_id, client_secret))
            ).decode("ascii")
            headers.update({'Authorization': 'Basic {}'.format(userpass,)})
        response = old_http_request(uri, headers=headers, data=data, method=method)

        # TODO: check if we may handle failed B2ACCESS response here
        return response

    remote.http_request = new_http_request
