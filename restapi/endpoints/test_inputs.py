# from datetime import datetime

# import pytz
from typing import Any

from restapi import decorators
from restapi.config import TESTING
from restapi.models import ISO8601UTC, Schema, fields, validate
from restapi.rest.definition import EndpointResource, Response

if TESTING:

    class InputSchema(Schema):
        mystr = fields.Str(required=True, validate=validate.Length(min=1))
        mydate = fields.DateTime(
            required=True,
            format=ISO8601UTC,
            # validate=validate.Range(
            #     max=datetime.now(pytz.utc).replace(hour=23, minute=59, second=59),
            #     min=datetime(1900, 1, 1, tzinfo=pytz.utc),
            #     max_inclusive=True,
            #     error="Invalid date",
            # ),
        )
        myint_exclusive = fields.Int(
            required=True,
            validate=validate.Range(
                min=1, max=10, min_inclusive=False, max_inclusive=False
            ),
        )
        myint_inclusive = fields.Int(
            required=True,
            validate=validate.Range(min=1, max=10),
        )

    class TestInputs(EndpointResource):
        @decorators.use_kwargs(InputSchema)
        @decorators.endpoint(
            path="/tests/inputs",
            summary="Accept input based on a rich model",
            description="Only enabled in testing mode",
            responses={204: "Tests executed"},
        )
        def post(self, **kwargs: Any) -> Response:

            return self.empty_response()
