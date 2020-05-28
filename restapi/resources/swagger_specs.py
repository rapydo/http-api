# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from flask import request, jsonify
from glom import glom
from restapi.confs import PRODUCTION, get_api_url
from restapi.rest.definition import EndpointResource
from restapi.utilities.globals import mem

from restapi.utilities.logs import log


class SwaggerSpecifications(EndpointResource):
    """
    Specifications output throught Swagger (open API) standards
    """

    labels = ["specifications"]

    _GET = {
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
        specs = mem.customizer._definitions

        api_url = get_api_url(request, PRODUCTION)
        scheme, host = api_url.rstrip('/').split('://')
        specs['host'] = host
        specs['schemes'] = [scheme]

        # Jsonify, so we skip custom response building
        return jsonify(specs)


class NewSwaggerSpecifications(MethodResource, EndpointResource):
    """
    Specifications output throught Swagger (open API) standards
    """

    labels = ["specifications"]

    _GET = {
        "/swagger": {
            "summary": "Endpoints specifications based on OpenAPI format",
            "responses": {
                "200": {
                    "description": "Endpoints JSON based on OpenAPI Specifications"
                }
            },
        }
    }

    def get(self):

        specs = mem.docs.spec.to_dict()

        api_url = get_api_url(request, PRODUCTION)
        scheme, host = api_url.rstrip('/').split('://')
        specs['host'] = host
        specs['schemes'] = [scheme]

        user = self.get_user_if_logged(
            allow_access_token_parameter=True
        )
        if user:
            return jsonify(specs)

        log.info("Unauthenticated request, filtering out private endpoints")
        # Remove sensible data
        filtered_specs = {}
        for key, data in specs.items():

            # Find endpoint mapping flagged as private
            if key == 'paths':
                for uri, endpoint in data.items():
                    for method, definition in endpoint.items():

                        u = uri.replace("{", "<").replace("}", ">")
                        is_private = glom(
                            mem.customizer._private_endpoints,
                            f"{u}.{method.upper()}",
                            default=False
                        )
                        if is_private:
                            log.critical("Skipping {} {}", method, uri)
                            continue

                        filtered_specs.setdefault(key, {})
                        filtered_specs[key].setdefault(uri, {})
                        filtered_specs[key][uri].setdefault(method, definition)
            elif key == 'definitions':
                filtered_specs.setdefault(key, {})
                for schema, definition in data.items():
                    filtered_specs[key].setdefault(schema, definition)
            else:
                filtered_specs.setdefault(key, data)

        return jsonify(filtered_specs)
