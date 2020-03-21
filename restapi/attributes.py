# -*- coding: utf-8 -*-

"""
Classes to mimic structured objects
defined with the help of the cool library @attr.s
"""

from attr import s as ClassOfAttributes, ib as attribute

ALL_ROLES = 'all'
ANY_ROLE = 'any'


########################
# All attributes we use for a Flask Response
########################
@ClassOfAttributes
class ResponseElements:
    defined_content = attribute()
    elements = attribute(default=None)
    code = attribute(default=None)
    errors = attribute(default=None)
    headers = attribute(default={})
    meta = attribute(default=None)
    head_method = attribute(default=False)


########################
# Definition for extra custom attributes to EndpointElements
########################
@ClassOfAttributes
class ExtraAttributes:
    auth = attribute(default=[])
    publish = attribute(default=True)
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
