# -*- coding: utf-8 -*-

"""
App specifications
"""

# Little hack to avoid printing unwanted logs when cli is asking usage
from restapi import FLASK_HELP
if FLASK_HELP:
    raise LookupError
else:
    from flask_restful import Api as RestFulApi
    from restapi.rest.farmer import EndpointsFarmer
    from utilities.globals import mem
    from utilities.logs import get_logger
    log = get_logger(__name__)


class Api(RestFulApi):
    """
    Hack the original RESTful API class from the extension
    aiming at the removal of their response
    """

    def output(self, resource):
        """
        The original method here was trying to intercept the Response before
        Flask could build it, by writing a decorator on the resource and force
        'make_response' on unpacked elements.

        This ruins our plan of creating our standard response,
        so I am overriding it to JUST TO AVOID THE DECORATOR
        """
        return resource


def create_endpoints(epo):
    """
    Add all memorized resource (from swagger reading) into Flask-Restful
    """

    # Use configuration built with swagger
    resources = mem.customizer._endpoints

    # Basic configuration (simple): from example class
    if len(resources) < 1:
        log.warning("No custom endpoints found!")

        raise AttributeError("Follow the docs and define your endpoints")

    log.debug("Using resources defined within swagger")

    for resource in resources:
        # TODO: CHECK is there any way to remove farm.py ?
        epo.add(resource)

    # Enable all schema endpoints to be mapped with this extra step
    se = mem.customizer._schema_endpoint
    if len(se.uris) > 0:
        log.debug("Found one or more schema to expose")
        epo.add(se)

    return epo


# REST to be activated inside the app factory
log.verbose("Endpoints w/ %s-%s" % (Api.__name__, EndpointsFarmer.__name__))
