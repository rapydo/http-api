from datetime import datetime
from typing import Any

import pytz
from neomodel import DateTimeProperty, StringProperty, StructuredNode

from restapi.utilities.uuid import getUUID


# Base type StructuredNode becomes "Any" due to an unfollowed import
class IdentifiedNode(StructuredNode):  # type: ignore

    """
    A StructuredNode identified by an uuid
    """

    __abstract_node__ = True

    # UniqueIdProperty creates uuid in hex formata (without hyphes)
    # These are not compatible with marshmallow that serializes with UUID(value) so that
    # hex uuids are serialized with hyphes and this create divergences
    # uuid = UniqueIdProperty()
    uuid = StringProperty(default=getUUID, unique_index=True)


class TimestampedNode(IdentifiedNode):

    """
    An IdentifiedNode with creation and modification dates
    """

    __abstract_node__ = True

    created = DateTimeProperty(default_now=True, show=True)
    modified = DateTimeProperty(default_now=True, show=True)

    def save(self, *args: Any, **kwargs: Any) -> Any:
        self.modified = datetime.now(pytz.utc)
        return super().save(*args, **kwargs)
