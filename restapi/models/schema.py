import inspect
from typing import Any, Dict, Optional, Type, Union

from marshmallow import EXCLUDE
from marshmallow import Schema as MarshmallowSchema
from marshmallow import ValidationError, pre_load
from neomodel import StructuredNode, StructuredRel, properties

from restapi.models import fields
from restapi.utilities.logs import log

GET_SCHEMA_KEY = "get_schema"


class Schema(MarshmallowSchema):
    def __init__(self, strip_required: bool = False, *args: Any, **kwargs: Any) -> None:

        super().__init__(**kwargs)
        if strip_required:
            for k in self.declared_fields:
                self.declared_fields[k].required = False

    # Mypy does not accept the equivalence between
    # marshmallow.fields and restapi.models.fields
    # And cannot be blamed for that... it's a dirty implementation :-)
    @classmethod
    def from_dict(  # type: ignore
        cls, attributes: Dict[str, Union[fields.Field, type]], name: str
    ) -> type:
        return super().from_dict(attributes, name=name)  # type: ignore

    # instruct marshmallow to serialize data to a collections.OrderedDict
    class Meta:
        ordered = True

    # NOTE: self is not used, but @pre_load cannot be static
    @pre_load
    def raise_get_schema(self, data: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:

        if "access_token" in data:
            # valid for ImmutableMultiDict:
            data = data.to_dict()  # type: ignore
            data.pop("access_token")

        if GET_SCHEMA_KEY in data:
            raise ValidationError("Schema requested")
        return data


class PartialSchema(Schema):
    class Meta:
        ordered = True
        unknown = EXCLUDE


class Neo4jSchema(Schema):
    def __init__(
        self, model: Type[Any], fields: Optional[Any], *args: Any, **kwargs: Any
    ) -> None:
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

        self.fields = fields  # type: ignore
        # Leave the constructor to avoid variable shadowing between
        # this fields and the from marshmallow import fields above
        self.build_schema(model)

    def build_schema(self, model: Type[Any]) -> None:

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
                        self.declared_fields[attribute] = fields.Neo4jChoice(
                            prop.choices
                        )

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
