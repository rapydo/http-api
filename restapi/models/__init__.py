from typing import Any

from marshmallow import pre_load, validate
from webargs.flaskparser import parser

from restapi.models import fields
from restapi.models.schema import GET_SCHEMA_KEY, Neo4jSchema, PartialSchema, Schema
from restapi.types import FlaskRequest

__all__ = [
    "fields",
    "GET_SCHEMA_KEY",
    "Neo4jSchema",
    "pre_load",
    "Schema",
    "PartialSchema",
    "validate",
]


# ISO 8601 format with Zulu time (default format for Javascript Date)
ISO8601UTC = "%Y-%m-%dT%H:%M:%S.%fZ"


@parser.location_loader("body")
def load_data(request: FlaskRequest, schema: Schema) -> Any:
    # Return json if it is not None, otherwise it will send form
    # No merge is allowed here
    return request.json or request.form
