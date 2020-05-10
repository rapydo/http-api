# -*- coding: utf-8 -*-

"""
Add schema endpoint if you have models to expose
"""

from restapi.rest.definition import EndpointResource
from restapi import decorators
# from restapi.utilities.logs import log


class RecoverSchema(EndpointResource):
    @decorators.catch_errors()
    def get(self, **kwargs):
        """ Expose schemas for UIs automatic form building """

        # FIXME: not from json but from query
        method = self.get_input(single_parameter='method', default='POST')

        custom_definition = self.get_endpoint_custom_definition(
            method=method, is_schema_url=True
        )

        return self.response(custom_definition)
