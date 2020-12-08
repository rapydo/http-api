from restapi import decorators
from restapi.config import TESTING
from restapi.models import Schema, fields
from restapi.rest.definition import EndpointResource

if TESTING:

    class InputSchema(Schema):
        myfield1 = fields.Str(required=True)

    class TestInputs(EndpointResource):
        @decorators.use_kwargs(InputSchema)
        @decorators.endpoint(
            path="/tests/inputs",
            summary="Accept input based on a rich model",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def post(self, **kwargs):

            return self.empty_response()
