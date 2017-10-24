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
    from restapi.rest import farmer, response
    from utilities.globals import mem
    from utilities.logs import get_logger
    log = get_logger(__name__)


def output_html(data, code, headers=None, array=False):

    from flask import Response, render_template
    html_data = {'body_content': data, 'array': array}
    html_page = render_template('index.html', **html_data)
    return Response(
        html_page,
        mimetype=response.MIMETYPE_HTML, status=code, headers=headers)


# def output_json(data, code, headers=None):
    # from flask import make_response
    # resp = make_response(data, code)
    # resp.headers.extend(headers or {})
    # return resp


class Api(RestFulApi):
    """
    Hack the original RESTful API class from the extension
    aiming at the removal of their response
    """

    # def __init__(self, *args, **kwargs):
    #     super(Api, self).__init__(*args, **kwargs)
    #     self.representations = {
    #         response.MIMETYPE_JSON: output_json,
    #         response.MIMETYPE_HTML: output_html,
    #         # There could be more, if needed
    #     }

    def output(self, resource):
        """
        The original method was trying to intercept the Response before
        Flask could build it, by writing a decorator on the resource and force
        'make_response' on unpacked elements.

        This ruins our plan of creating our standard response,
        so I am overriding it to do no harm
        """
        return resource


# Utility to create endpoints on a regular basis
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
        epo.add(resource)

    # Enable all schema endpoints to be mapped with this extra step
    se = mem.customizer._schema_endpoint
    if len(se.uris) > 0:
        log.debug("Found one or more schema to expose")
        epo.add(se)

    return epo


# REST to be activated inside the app factory
log.verbose(
    "Endpoints w/ %s-%s",
    Api.__name__, farmer.EndpointsFarmer.__name__
)
