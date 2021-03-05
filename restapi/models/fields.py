import json
import re

from marshmallow import ValidationError
from webargs import fields as webargs_fields

from restapi.config import TESTING
from restapi.utilities.logs import log


class Field(webargs_fields.Field):
    def __init__(
        self,
        *args,
        label=None,
        description=None,
        password=False,
        autocomplete=None,
        **kwargs,
    ):

        kwargs.setdefault("metadata", {})

        if label is not None:
            kwargs["metadata"].setdefault("label", label)

        if description is not None:
            kwargs["metadata"].setdefault("description", description)

        if autocomplete is not None:
            kwargs["metadata"].setdefault("autocomplete", autocomplete)

        kwargs["metadata"].setdefault("password", password)

        super().__init__(*args, **kwargs)

    pass


####################################################################################
#               1) Include all types from webargs to this custom module
####################################################################################


class AwareDateTime(Field, webargs_fields.AwareDateTime):
    pass


class Bool(Field, webargs_fields.Bool):
    pass


class Boolean(Field, webargs_fields.Boolean):
    pass


class Constant(Field, webargs_fields.Constant):
    pass


class Date(Field, webargs_fields.Date):
    pass


class DateTime(Field, webargs_fields.DateTime):
    pass


class Decimal(Field, webargs_fields.Decimal):
    pass


class Dict(Field, webargs_fields.Dict):
    pass


class Email(Field, webargs_fields.Email):
    pass


class Float(Field, webargs_fields.Float):
    pass


class Function(Field, webargs_fields.Function):
    pass


class Int(Field, webargs_fields.Int):
    pass


class Integer(Field, webargs_fields.Integer):
    pass


class Mapping(Field, webargs_fields.Mapping):
    pass


class Method(Field, webargs_fields.Method):
    pass


class NaiveDateTime(Field, webargs_fields.NaiveDateTime):
    pass


class Number(Field, webargs_fields.Number):
    pass


class Raw(Field, webargs_fields.Raw):
    pass


class Str(Field, webargs_fields.Str):
    pass


class String(Field, webargs_fields.String):
    pass


class TimeDelta(Field, webargs_fields.TimeDelta):
    pass


class URL(Field, webargs_fields.URL):
    pass


class Url(Field, webargs_fields.Url):
    pass


class UUID(Field, webargs_fields.UUID):
    pass


####################################################################################
#   2) Override some types with custom implementation to extend functionalities
####################################################################################
class List(Field, webargs_fields.List):
    def __init__(self, *args, unique=False, min_items=0, **kwargs):
        self.unique = unique
        self.min_items = min_items

        super().__init__(*args, **kwargs)

    def _deserialize(self, value, attr, data, **kwargs):

        # this is the case when requests (or pytest) send some json-dumped lists
        # for example for a multi-value select
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except BaseException as e:
                log.warning(e)

        value = super()._deserialize(value, attr, data, **kwargs)

        if not isinstance(value, list):  # pragma: no cover
            raise ValidationError("Invalid type")

        if self.unique:
            value = list(set(value))

        if len(value) < self.min_items:
            raise ValidationError(
                f"Expected at least {self.min_items} items, received {len(value)}"
            )

        return value


class Nested(Field, webargs_fields.Nested):
    def _deserialize(self, value, attr, data, **kwargs):

        # this is the case when requests (or pytest) send some json-dumped object
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except BaseException as e:  # pragma: no cover
                log.warning(e)
        super()._deserialize(value, attr, data, **kwargs)


class DelimitedList(Field, webargs_fields.DelimitedList):
    def __init__(self, *args, unique=False, **kwargs):
        self.unique = unique

        super().__init__(*args, **kwargs)

    def _deserialize(self, value, attr, data, **kwargs):

        values = super()._deserialize(value, attr, data, **kwargs)

        if self.unique and len(values) != len(set(values)):
            raise ValidationError("Provided list contains duplicates")

        return values


####################################################################################
#                   3) Add some additional custom fields
####################################################################################


class Neo4jChoice(Field):
    """Field that serializes from a neo4j choice"""

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


class Neo4jRelationshipToMany(Nested):
    # nested_obj: StructuredRel
    def _serialize(self, nested_obj, attr, obj, **kwargs):
        self.many = True
        return super()._serialize(nested_obj.all(), attr, obj, **kwargs)


class Neo4jRelationshipToSingle(Nested):
    # nested_obj: StructuredRel
    def _serialize(self, nested_obj, attr, obj, **kwargs):
        self.many = False
        self.schema.many = False
        return super()._serialize(nested_obj.single(), attr, obj, **kwargs)


class Neo4jRelationshipToCount(Int):
    # value: StructuredRel
    def _serialize(self, value, attr, obj, **kwargs):
        return self._format_num(len(value))


class TOTP(String):
    def _deserialize(self, value, attr, data, **kwargs):

        value = super()._deserialize(value, attr, data, **kwargs)

        if not re.match(r"^[0-9]{6}$", value):
            if TESTING:
                log.error("Invalid TOTP format: {}", value)
            raise ValidationError("Invalid TOTP format")

        return value
