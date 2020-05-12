# -*- coding: utf-8 -*-

from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector
from restapi.exceptions import RestApiException
from restapi import decorators


class Verify(EndpointResource):
    """ Service connection testing """

    labels = ["helpers"]
    GET = {
        "/status/<service>": {
            "summary": "Check if the API server is able to reach a given service",
            "description": "Use this URI to check the connection between APIs and services",
            "responses": {
                "200": {"description": "Server is able to reach the service"}
            },
        }
    }

    @decorators.catch_errors()
    @decorators.auth.required(roles=['admin_root'])
    def get(self, service):

        if not detector.check_availability(service):
            raise RestApiException(
                "Unknown service: {}".format(service),
                status_code=404,
            )

        self.get_service_instance(service, global_instance=False)
        return self.response("Service is reachable: {}".format(service))
