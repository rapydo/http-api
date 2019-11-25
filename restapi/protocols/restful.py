# -*- coding: utf-8 -*-

"""
App specifications
"""

# Little hack to avoid printing unwanted logs when cli is asking usage
from restapi import FLASK_HELP

if FLASK_HELP:
    raise LookupError
else:
    from flask_restful import Api as RestFulApi


class Api(RestFulApi):
    """
    Hack the original RESTful API class from the extension
    aiming at the removal of their response
    """

    def output(self, resource):
        """
        The original method was trying to intercept the Response before
        Flask could build it, by writing a decorator on the resource and force
        'make_response' on unpacked elements.

        This ruins our plan of creating our standard response,
        so I am overriding it to do no harm
        """
        return resource
