# -*- coding: utf-8 -*-
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException
from restapi import decorators as decorate

from flask_apispec import use_kwargs, marshal_with
from flask_apispec import MethodResource
from webargs import fields
from marshmallow import Schema

from restapi.utilities.logs import log


class UserSchema(Schema):
    name = fields.Str(required=True)
    email = fields.Email(required=True)
    created_at = fields.DateTime(required=True)


class Wrapper(Schema):
    data: dict()


class Error(Schema):
    error: fields.Str()


class old_responses(Schema):
    defined_content = fields.Str()
    errors = fields.Str()


class OutSchema(Schema):
    value = fields.Int()


class OutSchema1(Schema):
    value = fields.Str()


class ApiSpecsPoC(MethodResource, EndpointResource):

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
    @marshal_with(Error, code=400)
    @marshal_with(Error, code=404)
    @marshal_with(old_responses, code=200)
    # @marshal_with(OutSchema, code=200)
    @marshal_with(OutSchema1, code=201)
    @marshal_with(None, code=204)
    @decorate.catch_error()
    def get(self, **kwargs):

        log.critical(kwargs)

        # return self.force_response("blabla")
        data = {"mydata": "123", "xyz": "abc"}
        errors = ["x", "y"]
        return self.force_response(data, errors=errors)
        raise RestApiException("Just an error")

        return {"value": '10'}, 200
        # return {"value": '10'}, 201
