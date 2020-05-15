# -*- coding: utf-8 -*-

from flask import jsonify
from restapi.rest.definition import EndpointResource
from restapi.utilities.globals import mem


class SwaggerSpecifications(EndpointResource):
    """
    Specifications output throught Swagger (open API) standards
    """

    labels = ["specifications"]

    GET = {
        "/specs": {
            "summary": "Specifications output throught Swagger (open API) standards",
            "responses": {
                "200": {
                    "description": "Endpoints JSON based on OpenAPI Specifications"
                }
            },
        }
    }

    def get(self):

        # NOTE: swagger dictionary is read only once, at server init time
        swagjson = mem.customizer._definitions

        # NOTE: changing dinamically options, based on where the client lies
        from restapi.confs import PRODUCTION
        from restapi.confs import get_api_url
        from flask import request

        api_url = get_api_url(request, PRODUCTION)
        scheme, host = api_url.rstrip('/').split('://')
        swagjson['host'] = host
        swagjson['schemes'] = [scheme]

        # Jsonify, so we skip custom response building
        return jsonify(swagjson)
