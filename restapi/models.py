
from marshmallow import Schema as MarshmallowSchema
from marshmallow import ValidationError, pre_load, fields

GET_SCHEMA_KEY = 'get_schema'


class Schema(MarshmallowSchema):
    def __init__(self, strip_required=False, *args, **kwargs):
        super(Schema, self).__init__(**kwargs)
        if strip_required:
            for k in self.declared_fields:
                self.declared_fields[k].required = False
    # A fake field user to force return of schemas
    get_schema = fields.Bool(
        required=False,
        description="Request schema specifications"
    )

    # instruct marshmallow to serialize data to a collections.OrderedDict
    class Meta:
        ordered = True

    # NOTE: self is not used, but @pre_load cannot be static
    @pre_load
    def raise_get_schema(self, data, **kwargs):
        if GET_SCHEMA_KEY in data:
            raise ValidationError('Schema requested')
        return data
