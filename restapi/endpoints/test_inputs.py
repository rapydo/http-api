from datetime import datetime
from typing import Any, Optional

import pytz

from restapi import decorators
from restapi.config import TESTING
from restapi.connectors import Connector
from restapi.models import ISO8601UTC, Schema, fields, validate
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import User

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
        MYDATE = fields.AwareDateTime(
            required=True,
            format=ISO8601UTC,
            default_timezone=pytz.utc,
            validate=validate.Range(
                max=datetime.now(pytz.utc).replace(hour=23, minute=59, second=59),
                min=datetime(1900, 1, 1, tzinfo=pytz.utc),
                max_inclusive=True,
                error="Invalid date",
            ),
        )
        myint_exclusive = fields.Int(
            required=True,
            # Explicit label definition... but missing description
            validate=validate.Range(
                min=1, max=10, min_inclusive=False, max_inclusive=False
            ),
            metadata={
                "label": "Int exclusive field",
            },
        )
        myint_inclusive = fields.Int(
            required=True,
            # Both label and description explicit definition
            validate=validate.Range(min=1, max=10),
            metadata={
                "label": "Int inclusive field",
                "description": "This field accepts values in a defined range",
            },
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

        # Note: requests (from pytest) has to json-dump the arrays and objects,
        # but the normal Marshmallow fields does not json-load the inputs

        # fields.Nested is a replacement of the default Nested field with the ability
        # to receive json dumped data from requests or pytest
        mynested = fields.Nested(Nested, required=True)

        mynullablenested = fields.Nested(Nested, required=True, allow_none=True)

        # fields.List is a replacement of the default List field with the ability
        # to receive json dumped data from requests or pytest

        # In json model the type of this field will be resolved as string[]
        mylist = fields.List(fields.Str(), required=True)
        # In json model the type of this field will be resolved as int[]
        mylist2 = fields.List(CustomInt, required=True)
        # In json model the type of this field will be resolved as mylist3[]
        # The type is key[] ... should be something more explicative like FieldName[]
        mylist3 = fields.List(CustomGenericField, required=True)

    class TestInputs(EndpointResource):
        @decorators.auth.optional(allow_access_token_parameter=True)
        @decorators.use_kwargs(InputSchema)
        @decorators.endpoint(
            path="/tests/inputs",
            summary="Accept inputs based on a rich model",
            description="Only enabled in testing mode",
            responses={204: "Tests executed"},
        )
        def post(self, user: Optional[User], **kwargs: Any) -> Response:

            return self.empty_response()


if TESTING and Connector.check_availability("neo4j"):

    CHOICES = (("A", "AAA"), ("B", "BBB"), ("C", "CCC"))

    class InputNeo4jSchema(Schema):
        # include a Neo4jChoice to test the deserialize
        choice = fields.Neo4jChoice(CHOICES, required=True)

    class UUID(Schema):
        uuid = fields.String()

    class TOKEN(Schema):
        token_type = fields.String()

    class OutputNeo4jSchema(Schema):
        # include a Neo4jChoice to test the serialize
        choice = fields.Neo4jChoice(CHOICES)
        relationship_many = fields.Neo4jRelationshipToMany(TOKEN)
        relationship_single = fields.Neo4jRelationshipToSingle(UUID)
        relationship_count = fields.Neo4jRelationshipToCount()

    class TestNeo4jInputs(EndpointResource):
        @decorators.auth.require()
        @decorators.use_kwargs(InputNeo4jSchema)
        @decorators.marshal_with(OutputNeo4jSchema)
        @decorators.endpoint(
            path="/tests/neo4jinputs",
            summary="Accept inputs based on a neo4j-related schema",
            responses={204: "Tests executed"},
        )
        def post(self, choice: str, user: User) -> Response:

            data = {
                "choice": choice,
                "relationship_many": user.tokens,
                "relationship_single": user.belongs_to,
                "relationship_count": user.tokens,
            }
            return self.response(data)
