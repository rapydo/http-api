from restapi import decorators
from restapi.config import TESTING
from restapi.models import ISO8601UTC, Schema, fields
from restapi.rest.definition import EndpointResource

if TESTING:

    class InputSchema(Schema):
        mystr = fields.Str(required=True)
        mydate = fields.DateTime(required=True, format=ISO8601UTC)

    class TestInputs(EndpointResource):
        @decorators.use_kwargs(InputSchema)
        @decorators.endpoint(
            path="/tests/inputs",
            summary="Accept input based on a rich model",
            description="Only enabled in testing mode",
            responses={204: "Tests executed"},
        )
        def post(self, **kwargs):

            return self.empty_response()
