# from datetime import datetime

# import pytz
from typing import Any

from restapi import decorators
from restapi.config import TESTING
from restapi.models import ISO8601UTC, Schema, fields, validate
from restapi.rest.definition import EndpointResource, Response

if TESTING:

    class Nested(Schema):
        nestedstr = fields.Str(required=True)

    class CustomInt(fields.Int):
        pass

    class CustomGenericField(fields.Field):
        pass

    class InputSchema(Schema):
        # lowercase key without label defined. label will be key.title() in schema
        mystr = fields.Str(required=True, validate=validate.Length(min=4))
        # non-lowercase key without label defined. label will be == to key in schema
        MYDATE = fields.DateTime(
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
            # Explicit label definition... but missing description
            label="Int exclusive field",
            validate=validate.Range(
                min=1, max=10, min_inclusive=False, max_inclusive=False
            ),
        )
        myint_inclusive = fields.Int(
            required=True,
            # Both label and description explicit definition
            label="Int inclusive field",
            description="This field accepts values in a defined range",
            validate=validate.Range(min=1, max=10),
        )

        myselect = fields.Str(
            required=True,
            validate=validate.OneOf(choices=["a", "b"], labels=["A", "B"]),
        )

        myselect2 = fields.Str(
            required=True,
            # Wrong definition, number labels < number of choices
            # Labels will be ignored and replaced by choices
            validate=validate.OneOf(choices=["a", "b"], labels=["A"]),
        )

        mymaxstr = fields.Str(required=True, validate=validate.Length(max=7))

        myequalstr = fields.Str(required=True, validate=validate.Length(equal=6))

        mynested = fields.Nested(Nested, required=True)

        # In json model the type of this field will be resolved as string[]
        mylist = fields.List(fields.Str(), required=True)
        # In json model the type of this field will be resolved as int[]
        mylist2 = fields.List(CustomInt, required=True)
        # In json model the type of this field will be resolved as mylist3[]
        # The type is key[] ... should be something more explicative like FieldName[]
        mylist3 = fields.List(CustomGenericField, required=True)

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
