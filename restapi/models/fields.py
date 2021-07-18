import json
import re
from typing import Any, Mapping, Optional, Union

from marshmallow import ValidationError, types
from marshmallow.utils import missing as missing_
from webargs import fields as webargs_fields

from restapi.config import TESTING
from restapi.utilities.logs import log


class Field(webargs_fields.Field):
    def __init__(
        self,
        *,
        required: bool = False,
        label: Optional[str] = None,
        description: Optional[str] = None,
        password: bool = False,
        autocomplete_endpoint: Optional[str] = None,
        autocomplete_show_id: bool = False,
        autocomplete_id_bind: Optional[str] = None,
        autocomplete_label_bind: Optional[str] = None,
        **kwargs: Any,
    ) -> None:

        kwargs.setdefault("metadata", {})

        if label is not None:
            kwargs["metadata"].setdefault("label", label)

        if description is not None:
            kwargs["metadata"].setdefault("description", description)

        if autocomplete_endpoint is not None:
            kwargs["metadata"].setdefault(
                "autocomplete_endpoint", autocomplete_endpoint
            )
            kwargs["metadata"].setdefault("autocomplete_show_id", autocomplete_show_id)

        if autocomplete_id_bind is not None:
            kwargs["metadata"].setdefault("autocomplete_id_bind", autocomplete_id_bind)

        if autocomplete_label_bind is not None:
            kwargs["metadata"].setdefault(
                "autocomplete_label_bind", autocomplete_label_bind
            )

        kwargs["metadata"].setdefault("password", password)

        super().__init__(required=required, **kwargs)


####################################################################################
#               1) Include all types from webargs to this custom module
####################################################################################


# Base types


class Boolean(Field, webargs_fields.Boolean):
    pass


class DateTime(Field, webargs_fields.DateTime):
    pass


# Should extend Mapping... but I'm not using Mapping so let's directly extend from Field
class Dict(webargs_fields.Dict, Field):
    def __init__(
        self,
        keys: Optional[Union[Field, type]] = None,
        values: Optional[Union[Field, type]] = None,
        **kwargs: Any,
    ) -> None:

        super().__init__(keys, values, **kwargs)


class Number(Field, webargs_fields.Number):
    pass


class String(Field, webargs_fields.String):
    def _deserialize(
        self,
        value: Any,
        attr: Optional[str],
        data: Optional[Mapping[str, Any]],
        **kwargs: Any,
    ) -> Any:
        value = super()._deserialize(value, attr, data, **kwargs)
        if value:
            value = value.strip()
        return value


# Derived/child types

# Child of DateTime, as defined in marshmallow.fields
class AwareDateTime(DateTime, webargs_fields.AwareDateTime):
    pass


# Child of DateTime, as defined in marshmallow.fields
class Date(DateTime, webargs_fields.Date):
    pass


# Child of Number, as defined in marshmallow.fields
class Decimal(Number, webargs_fields.Decimal):
    pass


# Child of String, as defined in marshmallow.fields
class Email(String, webargs_fields.Email):
    pass


# Child of Number, as defined in marshmallow.fields
class Integer(Number, webargs_fields.Integer):
    pass


# Child of Number, as defined in marshmallow.fields
class Float(Number, webargs_fields.Float):
    pass


# Child of DateTime, as defined in marshmallow.fields
class NaiveDateTime(DateTime, webargs_fields.NaiveDateTime):
    pass


# Child of String, as defined in marshmallow.fields
class Url(String, webargs_fields.Url):
    pass


# Child of String, as defined in marshmallow.fields
class UUID(String, webargs_fields.UUID):
    pass


# Aliases, as defined in
# https://github.com/marshmallow-code/marshmallow/blob/dev/src/marshmallow/fields.py
URL = Url
Str = String
Bool = Boolean
Int = Integer


####################################################################################
#   2) Override some types with custom implementation to extend functionalities
####################################################################################
class List(webargs_fields.List, Field):
    def __init__(
        self,
        cls_or_instance: Union[webargs_fields.Field, type],
        *,
        unique: bool = False,
        min_items: int = 0,
        **kwargs: Any,
    ) -> None:
        super().__init__(cls_or_instance, **kwargs)
        self.unique = unique
        self.min_items = min_items

    def _deserialize(
        self,
        value: Any,
        attr: Optional[str],
        data: Optional[Mapping[str, Any]],
        **kwargs: Any,
    ) -> Any:

        # this is the case when requests (or pytest) send some json-dumped lists
        # for example for a multi-value select
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except Exception:
                pass

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


class Nested(webargs_fields.Nested, Field):
    def __init__(
        self,
        # nested: Union[SchemaABC, type, str, Callable[[], SchemaABC]],
        # the above type is from marshmallow, but it fails with Dict[str, Any] (imc)
        nested: Any,
        *,
        default: Any = missing_,
        only: Optional[types.StrSequenceOrSet] = None,
        exclude: types.StrSequenceOrSet = (),
        many: bool = False,
        unknown: Optional[str] = None,
        **kwargs: Any,
    ):

        super().__init__(
            nested,
            default=default,
            only=only,
            exclude=exclude,
            many=many,
            unknown=unknown,
            **kwargs,
        )

    # Probably due to the double parents: Nested(Field, webargs_fields.Nested)
    # Signature of "_deserialize" incompatible with supertype "Nested"
    def _deserialize(  # type: ignore
        self,
        value: Any,
        attr: Optional[str],
        data: Optional[Mapping[str, Any]],
        **kwargs: Any,
    ) -> Any:

        # this is the case when requests (or pytest) send some json-dumped object
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except Exception as e:  # pragma: no cover
                log.warning(e)
        return super()._deserialize(value, attr, data, **kwargs)


# DelimitedList is child of List as defined in:
# https://github.com/marshmallow-code/webargs/blob/dev/src/webargs/fields.py
class DelimitedList(webargs_fields.DelimitedList, List):
    def __init__(
        self,
        cls_or_instance: Union[webargs_fields.Field, type],
        *,
        delimiter: Optional[str] = None,
        unique: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(cls_or_instance, delimiter=delimiter, **kwargs)
        # Note: Can't use self.unique otherwise the elements will be silently cleaned
        # by the custom List deserializer
        # self.unique = unique
        self.no_duplicates = unique

    def _deserialize(
        self,
        value: Any,
        attr: Optional[str],
        data: Optional[Mapping[str, Any]],
        **kwargs: Any,
    ) -> Any:

        if not value:
            return value

        values = super()._deserialize(value, attr, data, **kwargs)

        if self.no_duplicates and len(values) != len(set(values)):
            raise ValidationError("Input list contains duplicates")

        return values


####################################################################################
#                   3) Add some additional custom fields
####################################################################################


# Should be extended to automatically include the choices as validation field to be
# Converted as a select on frontend
class Neo4jChoice(Field):
    """Field that serializes from a neo4j choice"""

    # choice_model is the same used in neo4j model as choices=
    def __init__(self, choices_model: Any, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if isinstance(choices_model, dict):
            self.choices_dict = choices_model
        else:
            # convert the tuple of tuple into as a dictionary for convenience
            self.choices_dict = {}
            for k, v in choices_model:
                self.choices_dict.setdefault(k, v)

    def _serialize(self, value: Any, attr: str, obj: Any, **kwargs: Any) -> Any:
        return {
            "key": value,
            # the value correspondance from choices_dict or value as default
            "description": self.choices_dict.get(value, value),
        }

    def _deserialize(
        self,
        value: Any,
        attr: Optional[str],
        data: Optional[Mapping[str, Any]],
        **kwargs: Any,
    ) -> Any:
        return value


class Neo4jRelationshipToMany(Nested):
    # nested_obj: StructuredRel
    # Probably due to the double parents: Nested(Field, webargs_fields.Nested)
    # Signature of "_serialize" incompatible with supertype "Field"
    def _serialize(  # type: ignore
        self, nested_obj: Any, attr: str, obj: Any, **kwargs: Any
    ) -> Any:
        self.many = True
        return super()._serialize(nested_obj.all(), attr, obj, **kwargs)


class Neo4jRelationshipToSingle(Nested):
    # nested_obj: StructuredRel
    # Probably due to the double parents: Nested(Field, webargs_fields.Nested)
    # Signature of "_serialize" incompatible with supertype "Field"

    def _serialize(  # type: ignore
        self, nested_obj: Any, attr: str, obj: Any, **kwargs: Any
    ) -> Any:
        self.many = False
        self.schema.many = False
        return super()._serialize(nested_obj.single(), attr, obj, **kwargs)


class Neo4jRelationshipToCount(Int):
    # value: StructuredRel
    def _serialize(self, value: Any, attr: str, obj: Any, **kwargs: Any) -> Any:
        return self._format_num(len(value))


class TOTP(String):
    def _deserialize(
        self,
        value: Any,
        attr: Optional[str],
        data: Optional[Mapping[str, Any]],
        **kwargs: Any,
    ) -> Any:

        value = super()._deserialize(value, attr, data, **kwargs)

        if not re.match(r"^[0-9]{6}$", value):
            if TESTING:
                log.error("Invalid TOTP format: {}", value)
            raise ValidationError("Invalid TOTP format")

        return value
