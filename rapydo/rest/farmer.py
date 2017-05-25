# -*- coding: utf-8 -*-

"""
Farmer that creates endpoints into REST service
"""

from rapydo.utils.logs import get_logger

log = get_logger(__name__)


class EndpointsFarmer(object):
    """ Handling endpoints creation"""

    rest_api = None

    def __init__(self, Api):
        super(EndpointsFarmer, self).__init__()
        # Init Restful plugin
        self.rest_api = Api(catch_all_404s=True)

    def add(self, resource):
        """ Adding a single restpoint from a Resource Class """

        from rapydo.protocols.bearer import authentication

        # Apply authentication: if required from yaml configuration
        # Done per each method
        for method, attributes in resource.custom['methods'].items():

            # If auth has some role, they have been validated
            # and authentication has been requested
            # if len(attributes.auth) < 1:
            #     continue
            # else:
            #     roles = attributes.auth

            roles = attributes.auth
            if roles is None:
                continue

            # Programmatically applying the authentication decorator
            # TODO: should this be moved to Meta class?
            # there is another similar piece of code in swagger.py
            original = getattr(resource.cls, method)
            decorated = authentication.authorization_required(
                original, roles=roles, from_swagger=True)
            setattr(resource.cls, method, decorated)

            if len(roles) < 1:
                roles = "'DEFAULT'"
            log.very_verbose("Auth on %s.%s for %s"
                             % (resource.cls.__name__, method, roles))

        urls = [uri for _, uri in resource.uris.items()]

        # Create the restful resource with it;
        # this method is from RESTful plugin
        self.rest_api.add_resource(resource.cls, *urls)
        log.verbose("Map '%s' to %s", resource.cls.__name__, urls)
