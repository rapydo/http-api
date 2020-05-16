# -*- coding: utf-8 -*-

import pytz
from datetime import datetime
from neomodel import StructuredNode
from neomodel import UniqueIdProperty
from neomodel import DateTimeProperty

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
        return super(TimestampedNode, self).save(*args, **kwargs)
