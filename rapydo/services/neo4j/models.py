# NEOMODEL BASE CLASSES EXTENSION #
import inspect
import pytz
from datetime import datetime
from neomodel import StringProperty as originalStringProperty
from neomodel import IntegerProperty as originalIntegerProperty
from neomodel import FloatProperty as originalFloatProperty
from neomodel import BooleanProperty as originalBooleanProperty
from neomodel import DateProperty as originalDateProperty
from neomodel import DateTimeProperty as originalDateTimeProperty
from neomodel import JSONProperty as originalJSONProperty
from neomodel import ArrayProperty as originalArrayProperty
from neomodel import EmailProperty as originalEmailProperty
from neomodel import AliasProperty as originalAliasProperty
# from neomodel import UniqueIdProperty as originalUniqueIdProperty
from neomodel import StructuredNode as originalStructuredNode
from neomodel import StructuredRel as originalStructuredRel
from neomodel import RelationshipTo as originalRelationshipTo
from neomodel import RelationshipFrom as originalRelationshipFrom

from neomodel.relationship_manager import RelationshipDefinition

from rapydo.utils.uuid import getUUID


def RelationshipTo(
        cls_name, rel_type,
        show=None, is_restricted=False,
        *args, **kwargs):
    """
    Ovveride of the RelationshipTo function from neomodel
    It call the original function and save into the returned object
    (instance of class RelationshipDefinition) the custom flags, to be used
    in the follow_relationships method of StructuredNode class
    """

    rel = originalRelationshipTo(cls_name, rel_type, *args, **kwargs)
    rel.show = show
    rel.is_restricted = is_restricted
    return rel


def RelationshipFrom(
        cls_name, rel_type,
        show=None, is_restricted=False,
        *args, **kwargs):
    """
    Ovveride of the RelationshipFrom function from neomodel
    It call the original function and save into the returned object
    (instance of class RelationshipDefinition) the custom flags, to be used
    in the follow_relationships method of StructuredNode class
    """

    rel = originalRelationshipFrom(cls_name, rel_type, *args, **kwargs)
    rel.show = show
    rel.is_restricted = is_restricted
    return rel


class myAttribProperty(object):
    """
    This class is used to save custom flags assigned to a property, to be used
    in the show_fields method of StructuredNode class.
    This class name is also used in the method above to filter out attributes
    not customized
    """
    show = False
    is_restricted = False

    def save_extra_info(self, show=None, is_restricted=False):

        if show is not None:
            self.show = show

        if is_restricted is not None:
            self.is_restricted = is_restricted


class StringProperty(originalStringProperty, myAttribProperty):
    """
    Customized version of StringProperty implemented in neomodel
    """

    def __init__(self, show=None, is_restricted=False, *args, **kwargs):
        self.save_extra_info(show, is_restricted)
        super(StringProperty, self).__init__(*args, **kwargs)


class IntegerProperty(originalIntegerProperty, myAttribProperty):
    """
    Customized version of IntegerProperty implemented in neomodel
    """

    def __init__(self, show=None, is_restricted=False, *args, **kwargs):
        self.save_extra_info(show, is_restricted)
        super(IntegerProperty, self).__init__(*args, **kwargs)


class FloatProperty(originalFloatProperty, myAttribProperty):
    """
    Customized version of FloatProperty implemented in neomodel
    """

    def __init__(self, show=None, is_restricted=False, *args, **kwargs):
        self.save_extra_info(show, is_restricted)
        super(FloatProperty, self).__init__(*args, **kwargs)


class BooleanProperty(originalBooleanProperty, myAttribProperty):
    """
    Customized version of BooleanProperty implemented in neomodel
    """

    def __init__(self, show=None, is_restricted=False, *args, **kwargs):
        self.save_extra_info(show, is_restricted)
        super(BooleanProperty, self).__init__(*args, **kwargs)


class DateTimeProperty(originalDateTimeProperty, myAttribProperty):
    """
    Customized version of DateTimeProperty implemented in neomodel
    """

    def __init__(self, show=None, is_restricted=False, *args, **kwargs):
        self.save_extra_info(show, is_restricted)
        super(DateTimeProperty, self).__init__(*args, **kwargs)


class DateProperty(originalDateProperty, myAttribProperty):
    """
    Customized version of DateProperty implemented in neomodel
    """

    def __init__(self, show=None, is_restricted=False, *args, **kwargs):
        self.save_extra_info(show, is_restricted)
        super(DateProperty, self).__init__(*args, **kwargs)


class ArrayProperty(originalArrayProperty, myAttribProperty):
    """
    Customized version of ArrayProperty implemented in neomodel
    """

    # BUG FIX: added base_property, as done in the original neomodel class
    # with commit c4faec6 on 14 Mar 2017
    # Releted issue: https://github.com/robinedwards/neomodel/issues/237
    def __init__(self, base_property=None, show=None, is_restricted=False,
                 *args, **kwargs):

        self.save_extra_info(show, is_restricted)
        super(ArrayProperty, self).__init__(base_property, *args, **kwargs)


class JSONProperty(originalJSONProperty, myAttribProperty):
    """
    Customized version of JSONProperty implemented in neomodel
    """

    def __init__(self, show=None, is_restricted=False, *args, **kwargs):
        self.save_extra_info(show, is_restricted)
        super(JSONProperty, self).__init__(*args, **kwargs)


class EmailProperty(originalEmailProperty, myAttribProperty):
    """
    Customized version of EmailProperty implemented in neomodel
    """

    def __init__(self, show=None, is_restricted=False, *args, **kwargs):
        self.save_extra_info(show, is_restricted)
        super(EmailProperty, self).__init__(*args, **kwargs)


class AliasProperty(originalAliasProperty, myAttribProperty):
    """
    Customized version of AliasProperty implemented in neomodel
    """

    def __init__(self, show=None, is_restricted=False, *args, **kwargs):
        self.save_extra_info(show, is_restricted)
        super(AliasProperty, self).__init__(*args, **kwargs)


# class UniqueIdProperty(originalDateTimeProperty, myAttribProperty):
#     """
#     Customized version of UniqueIdProperty implemented in neomodel
#     """
#     def __init__(self, show=None, is_restricted=False, *args, **kwargs):
#         self.save_extra_info(show, is_restricted)
#         super(UniqueIdProperty, self).__init__(*args, **kwargs)


class StructuredRel(originalStructuredRel):
    pass


class StructuredNode(originalStructuredNode):
    """
    Customized version of StructuredNode class implemented in neomodel
    This class exposes the show_fields and follow_relationships methods.
    These methods use custom flags set in myAttribProperty instances and in
    RelationshipDefinition instances (as modified by the custom functions
    RelationshipTo and RelationshipFrom)

    Note: abstract nodes to be used as base have to use a configuration like:
    http://j.mp/2o54N47 (neomodel readthedocs)
    """

    __abstract_node__ = True

    @classmethod
    def show_fields(cls, view_public_only=False):

        fields_to_show = []

        classes = inspect.getmro(cls)
        for cls_name in classes:
            if cls_name.__name__ == 'StructuredNode':
                break

            for c in cls_name.__dict__:
                attrib = getattr(cls, c)
                # print("fields:", cls.__name__, attrib)
                if not isinstance(attrib, myAttribProperty):
                    continue
                if not attrib.show:
                    continue
                if view_public_only and attrib.is_restricted:
                    continue

                fields_to_show.append(c)
        return fields_to_show

    @classmethod
    def follow_relationships(cls, view_public_only=False):

        relationship_to_follow = []

        classes = inspect.getmro(cls)
        for cls_name in classes:
            if cls_name.__name__ == 'StructuredNode':
                break

            for c in cls_name.__dict__:
                attrib = getattr(cls, c)
                if not isinstance(attrib, RelationshipDefinition):
                    continue
                if hasattr(attrib, 'show'):
                    show = getattr(attrib, 'show')
                else:
                    show = False
                if not show:
                    continue

                if view_public_only:
                    if hasattr(attrib, 'is_restricted'):
                        is_restricted = getattr(attrib, 'is_restricted')
                    else:
                        is_restricted = False
                    if is_restricted:
                        continue
                relationship_to_follow.append(c)
        return relationship_to_follow


class IdentifiedNode(StructuredNode):

    """
        A StructuredNode identified by an uuid
    """

    __abstract_node__ = True

    # TO FIX: now we should use:
    # uuid = UniqueIdProperty
    uuid = StringProperty(default=getUUID, unique_index=True)


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
