from datetime import datetime

import pytz
from neomodel import DateTimeProperty, StructuredNode, UniqueIdProperty


class IdentifiedNode(StructuredNode):

    """
        A StructuredNode identified by an uuid
    """

    __abstract_node__ = True

    uuid = UniqueIdProperty()


class TimestampedNode(IdentifiedNode):

    """
        An IdentifiedNode with creation and modification dates
    """

    __abstract_node__ = True

    created = DateTimeProperty(default_now=True, show=True)
    modified = DateTimeProperty(default_now=True, show=True)

    def save(self, *args, **kwargs):
        self.modified = datetime.now(pytz.utc)
        return super().save(*args, **kwargs)
