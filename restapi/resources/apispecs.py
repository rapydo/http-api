# -*- coding: utf-8 -*-
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException
from restapi import decorators as decorate

from flask_apispec import use_kwargs, marshal_with
from flask_apispec import MethodResource
# from flask_apispec import Ref
from marshmallow import Schema, fields, validate

from restapi.utilities.logs import log


class UserSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=4))
    email = fields.Email(required=True)
    age = fields.Int(required=True, validate=validate.Range(min=18, max=40))
    created_at = fields.DateTime(required=True)


class Error(Schema):
    error: fields.Str()


class old_responses(Schema):
    # Field that applies no formatting.
    data = fields.Raw(attribute="defined_content")
    errors = fields.List(fields.Str())
    # "Raw",
    # "Nested",
    # "Mapping",
    # "Dict",
    # "List",


class OutSchema(Schema):
    value = fields.Int()


class OutSchema1(Schema):
    value = fields.Str()


class ApiSpecsPoC(MethodResource, EndpointResource):

    labels = ['helpers']

    # schema = OutSchema

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
    @marshal_with(Error, code=400)
    @marshal_with(Error, code=404)
    @marshal_with(old_responses, code=200)
    # @marshal_with(OutSchema, code=200)
    @marshal_with(OutSchema1, code=201)
    @marshal_with(None, code=204)
    @decorate.catch_error()
    def get(self, **kwargs):

        log.info(kwargs)

        # return self.force_response("blabla")
        data = {"value": "123", "xyz": "abc"}
        errors = ["x", "y"]

        # return (errors, 400)
        return self.force_response(data, errors=errors, code=400)
        # raise RestApiException("Just an error")

        # return {"value": '10'}, 200
        # return {"value": '10'}, 201
