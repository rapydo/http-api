import re
from typing import Any, Mapping, Optional, Tuple, Union

import orjson
from marshmallow import ValidationError, types
from marshmallow.utils import missing as missing_
from webargs import fields

from restapi.config import TESTING
from restapi.utilities.logs import log

####################################################################################
#    1) Override some types with custom implementation to extend functionalities
####################################################################################


class String(fields.String):
    def _deserialize(
        self,
        value: Any,
        attr: Optional[str],
        data: Optional[Mapping[str, Any]],
        **kwargs: Any,
    ) -> Any:
        value = super()._deserialize(value, attr, data, **kwargs)
        if value and isinstance(value, str):
            value = value.strip()
        return value


class List(fields.List):
    def __init__(
        self,
        cls_or_instance: Union[fields.Field, type],
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
                value = orjson.loads(value)
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


class Nested(fields.Nested):
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

    def _deserialize(
        self,
        value: Any,
        attr: Optional[str],
        data: Optional[Mapping[str, Any]],
        partial: Optional[Union[bool, Tuple[str]]] = None,
        **kwargs: Any,
    ) -> Any:

        # this is the case when requests (or pytest) send some json-dumped object
        if isinstance(value, str):
            try:
                value = orjson.loads(value)
            except Exception as e:  # pragma: no cover
                log.warning(e)
        # This is because Nested is not typed on marshmallow
        return super()._deserialize(value, attr, data, **kwargs)  # type: ignore


# DelimitedList is child of List as defined in:
# https://github.com/marshmallow-code/webargs/blob/dev/src/webargs/fields.py
class DelimitedList(fields.DelimitedList, List):
    def __init__(
        self,
        cls_or_instance: Union[fields.Field, type],
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

        # This is because List is not typed on marshmallow
        values = super()._deserialize(value, attr, data, **kwargs)  # type: ignore

        if self.no_duplicates and len(values) != len(set(values)):
            raise ValidationError("Input list contains duplicates")

        return values


####################################################################################
#                   2) Add some additional custom fields
####################################################################################


# Should be extended to automatically include the choices as validation field to be
# Converted as a select on frontend
class Neo4jChoice(fields.Field):
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
    # value: StructuredRel
    # Signature of "_serialize" incompatible with supertype "Nested"
    # This is because Nested is not typed on marshmallow
    def _serialize(  # type: ignore
        self, value: Any, attr: str, obj: Any, **kwargs: Any
    ) -> Any:
        self.many = True
        # This is because Nested is not typed on marshmallow
        return super()._serialize(value.all(), attr, obj, **kwargs)  # type: ignore


class Neo4jRelationshipToSingle(Nested):
    # value: StructuredRel
    # Signature of "_serialize" incompatible with supertype "Nested"
    # This is because Nested is not typed on marshmallow
    def _serialize(  # type: ignore
        self,
        value: Any,
        attr: str,
        obj: Any,
        **kwargs: Any,
    ) -> Any:
        self.many = False
        self.schema.many = False
        # This is because Nested is not typed on marshmallow
        return super()._serialize(value.single(), attr, obj, **kwargs)  # type: ignore


class Neo4jRelationshipToCount(fields.Int):
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


####################################################################################
#                            3) Create some aliases
####################################################################################

Field = fields.Field
Boolean = fields.Boolean
DateTime = fields.DateTime
Dict = fields.Dict
Number = fields.Number
AwareDateTime = fields.AwareDateTime
Date = fields.Date
Decimal = fields.Decimal
Email = fields.Email
Integer = fields.Integer
Float = fields.Float
NaiveDateTime = fields.NaiveDateTime
Url = fields.Url
UUID = fields.UUID
# Aliases, as defined in
# https://github.com/marshmallow-code/marshmallow/blob/dev/src/marshmallow/fields.py
URL = Url
Str = String
Bool = Boolean
Int = Integer
