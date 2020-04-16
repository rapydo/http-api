
from marshmallow import Schema as MarshmallowSchema


class Schema(MarshmallowSchema):
    def __init__(self, strip_required=False, *args, **kwargs):
        super(Schema, self).__init__(**kwargs)
        if strip_required:
            for k in self.declared_fields:
                self.declared_fields[k].required = False
