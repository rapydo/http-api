# -*- coding: utf-8 -*-

from restapi.connectors import Connector
from restapi.utilities.meta import Meta
from restapi.utilities.logs import log


class Authenticator(Connector):

    def get_connection_exception(self):
        return None

    def preconnect(self, **kwargs):
        return True

    def postconnect(self, obj, **kwargs):
        return True

    def connect(self, **kwargs):

        # What service will hold authentication?
        auth_service = self.variables.get('service')
        auth_module = Meta.get_authentication_module(auth_service)
        return auth_module.Authentication()

    def initialize(self, pinit, pdestroy, abackend=None):

        obj = self.get_instance()
        # NOTE: Inject the backend as the object 'db' inside the instance
        # IMPORTANT!!! this is the 'hat trick' that makes things possible
        obj.db = abackend

        if pinit:
            with self.app.app_context():
                obj.init_users_and_roles()
                log.info("Initialized authentication module")

        if pdestroy:
            log.error("Destroy not implemented for authentication service")

        return obj
