# -*- coding: utf-8 -*-
from restapi.rest.definition import EndpointResource
from restapi import decorators as decorate

from flask_apispec import use_kwargs  # , marshal_with
from flask_apispec import MethodResource
from webargs import fields
from marshmallow import Schema

from restapi.utilities.logs import log


class UserSchema(Schema):
    name = fields.Str(required=True)
    email = fields.Email(required=True)
    created_at = fields.DateTime(required=True)


class ApiSpecsPOC(MethodResource, EndpointResource):

    labels = ['helpers']

    _GET = {
        "/apispec": {
            "summary": "Experiments with ApiSpec",
            "description": "Proof of concept for ApiSpec integration in RAPyDo",
            "responses": {"200": {"description": "Endpoint is working"}},
        }
    }

    # Example1
    # @use_kwargs({'species': fields.Int(required=True)})
    # def get(self, **kwargs):
    # Example2
    # @use_kwargs({'species': fields.Int(required=True)})
    # def get(self, species):
    # Example3
    @use_kwargs(UserSchema)
    @decorate.catch_error()
    def get(self, **kwargs):

        log.critical(kwargs)

        return 'Server is alive!'
