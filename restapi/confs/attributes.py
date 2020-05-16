# -*- coding: utf-8 -*-

"""
Classes to mimic structured objects
defined with the help of the cool library @attr.s
"""

from attr import s as ClassOfAttributes, ib as attribute

ALL_ROLES = 'all'
ANY_ROLE = 'any'


########################
# Definition for extra custom attributes to EndpointElements
########################
@ClassOfAttributes
class ExtraAttributes:
    auth = attribute(default=[])
    schema = attribute(default={})
    whatever = attribute(default=None)
    required_roles = attribute(default=ALL_ROLES)


########################
# Elements for endpoint configuration
########################
@ClassOfAttributes
class EndpointElements:
    exists = attribute(default=False)
    isbase = attribute(default=False)
    cls = attribute(default=None)
    uris = attribute(default={})
    methods = attribute(default=[])
    custom = attribute(default=ExtraAttributes())
    tags = attribute(default=[])
    base_uri = attribute(default='')
