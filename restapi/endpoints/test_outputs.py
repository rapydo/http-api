from datetime import datetime

from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource, Response

if TESTING:

    class TestOutputs(EndpointResource):
        # @decorators.marshal_with(OutputSchema)
        @decorators.endpoint(
            path="/tests/outputs/<out_type>",
            summary="Produce outputs based on the out_type url parameters",
            responses={200: "Tests executed"},
        )
        def post(self, out_type: str) -> Response:

            if out_type == "list":
                return self.response(["a", "b", "c", "c"])

            if out_type == "tuple":
                return self.response(("a", "b", "c", "c"))

            if out_type == "set":
                return self.response({"a", "b", "c", "c"})

            if out_type == "dict":
                return self.response({"a": 1, "b": 2, "c": 3})

            if out_type == "datetime":
                return self.response(datetime.now())

            return self.response("string")
