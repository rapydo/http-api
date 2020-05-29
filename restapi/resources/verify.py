from restapi.rest.definition import EndpointResource
from flask_apispec import MethodResource
from restapi.services.detect import detector
from restapi.exceptions import RestApiException
from restapi import decorators


class Verify(MethodResource, EndpointResource):
    """ Service connection testing """

    ALLOW_HTML_RESPONSE = True
    labels = ["helpers"]
    _GET = {
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
                f"Unknown service: {service}",
                status_code=404,
            )

        self.get_service_instance(service, global_instance=False)
        return self.response(f"Service is reachable: {service}")
