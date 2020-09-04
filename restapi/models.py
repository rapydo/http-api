import inspect

from marshmallow import Schema  # also used from endpoint for Schemas
from marshmallow import validate  # used as alias from endpoints
from marshmallow import EXCLUDE, ValidationError, pre_load
from neomodel import StructuredNode, StructuredRel, properties
from webargs import fields  # also imported from endpoints
from webargs.flaskparser import parser

from restapi.utilities.logs import log

# Note for SQL-Alchemy, consider to use:
# https://github.com/marshmallow-code/marshmallow-sqlalchemy

GET_SCHEMA_KEY = "get_schema"
# ISO 8601 format with Zulu time (default Javascript output)
ISO8601UTC = "%Y-%m-%dT%H:%M:%S.%fZ"

log.verbose("{} loaded", validate)


@parser.location_loader("body")
def load_data(request, schema):
    # Return json if it is not None, otherwise it will send form
    # No merge is allowed here
    return request.json or request.form


class InputSchema(Schema):
    def __init__(self, strip_required=False, *args, **kwargs):
        super().__init__(**kwargs)
        if strip_required:
            for k in self.declared_fields:
                self.declared_fields[k].required = False

    # A fake field used to force return of schemas
    get_schema = fields.Bool(
        required=False, description="Request schema specifications"
    )

    # instruct marshmallow to serialize data to a collections.OrderedDict
    class Meta:
        ordered = True

    # NOTE: self is not used, but @pre_load cannot be static
    @pre_load
    def raise_get_schema(self, data, **kwargs):
        if GET_SCHEMA_KEY in data:
            raise ValidationError("Schema requested")
        return data


class PartialInputSchema(InputSchema):
    class Meta:
        ordered = True
        unknown = EXCLUDE


class Neo4jSchema(Schema):
    def __init__(self, model, fields, *args, **kwargs):
        super().__init__(**kwargs)

        if not fields:
            fields = ()
        elif fields == "*":
            fields = None
        elif fields[0] == "*":
            fields = None
        elif isinstance(fields, tuple):
            pass
        elif isinstance(fields, list):
            pass
        else:  # pragma: no cover
            log.error("Invalid fields: {}", fields)
            fields = ()

        self.fields = fields
        # Leave the constructor to avoid variable shadowing between
        # this fields and the from marshmallow import fields above
        self.build_schema(model)

    def build_schema(self, model):

        # Get the full list of parent classes from model to object
        classes = inspect.getmro(model)

        starting_point = False
        # Iterate in reversed order to start from object
        for c in reversed(classes):
            # Skip all parentes up to StructuredNode and StructuredRel (included)
            if not starting_point:
                # Found the starting point, next class will be descended up to model
                if c == StructuredNode or c == StructuredRel:
                    starting_point = True
                # skip all parent up to StructuredNode and StructuredRel INCLUDED
                continue

            # Iterate all class attributes to find neomodel properties
            for attribute in c.__dict__:
                prop = getattr(c, attribute)

                if not isinstance(prop, properties.Property):
                    continue

                # self.fields can be None when the special value * is given in input
                if self.fields and attribute not in self.fields:
                    continue

                # log.info("Including property {}.{}", model.__name__, attribute)
                if isinstance(prop, properties.StringProperty):
                    if prop.choices is None:
                        self.declared_fields[attribute] = fields.Str()
                    else:
                        self.declared_fields[attribute] = Neo4jChoice(prop.choices)

                elif isinstance(prop, properties.BooleanProperty):
                    self.declared_fields[attribute] = fields.Boolean()
                elif isinstance(prop, properties.IntegerProperty):
                    self.declared_fields[attribute] = fields.Integer()
                elif isinstance(prop, properties.EmailProperty):
                    self.declared_fields[attribute] = fields.Email()
                elif isinstance(prop, properties.DateTimeProperty):
                    self.declared_fields[attribute] = fields.AwareDateTime()
                elif isinstance(prop, properties.UniqueIdProperty):
                    self.declared_fields[attribute] = fields.Str()
                else:  # pragma: no cover
                    log.error(
                        "Unsupport neomodel property: {}, fallback to StringProperty",
                        prop.__class__.__name__,
                    )
                    self.declared_fields[attribute] = fields.Str()


class Neo4jChoice(fields.Field):
    """Field that serializes from a neo4j choice
    """

    # choice_model is the same used in neo4j model as choices=
    def __init__(self, choices_model, **kwargs):
        super().__init__(**kwargs)
        if isinstance(choices_model, dict):
            self.choices_dict = choices_model
        else:
            # convert the tuple of tuple into as a dictionary for convenience
            self.choices_dict = {}
            for k, v in choices_model:
                self.choices_dict.setdefault(k, v)

    def _serialize(self, value, attr, obj, **kwargs):
        return {
            "key": value,
            # the value correspondance from choices_dict or value as default
            "description": self.choices_dict.get(value, value),
        }

    def _deserialize(self, value, attr, data, **kwargs):
        return value


class UniqueDelimitedList(fields.DelimitedList):
    def _deserialize(self, value, attr, data, **kwargs):
        values = super()._deserialize(value, attr, data, **kwargs)

        if len(values) != len(set(values)):
            raise ValidationError("Provided list contains duplicates")

        return values


class AdvancedList(fields.List):
    def __init__(self, *args, unique=False, min_items=0, **kwargs):
        self.unique = unique
        self.min_items = min_items
        super().__init__(*args, **kwargs)

    def _deserialize(self, value, attr, data, **kwargs):
        value = super()._deserialize(value, attr, data, **kwargs)

        if not isinstance(value, list):
            raise ValidationError("Invalid type")

        if self.unique:
            value = list(set(value))

        if len(value) < self.min_items:
            raise ValidationError(
                f"Expected at least {self.min_items} items, received {len(value)}"
            )

        return value
