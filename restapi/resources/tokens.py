# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from flask_apispec import marshal_with
from marshmallow import fields
from restapi.models import Schema
from restapi import decorators
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException

# from restapi.utilities.logs import log


class TokenSchema(Schema):
    id = fields.Str()
    IP = fields.Str()
    location = fields.Str()
    token = fields.Str()
    emitted = fields.DateTime()
    expiration = fields.DateTime()
    last_access = fields.DateTime()


class Tokens(MethodResource, EndpointResource):
    """ List all active tokens for a user """

    baseuri = "/auth"
    labels = ["authentication"]

    _GET = {
        "/tokens": {
            "summary": "Retrieve all tokens emitted for logged user",
            "responses": {"200": {"description": "List of tokens"}},
        }
    }
    _DELETE = {
        "/tokens/<token_id>": {
            "summary": "Remove specified token and make it invalid from now on",
            "responses": {"204": {"description": "Token has been invalidated"}},
        },
    }

    @marshal_with(TokenSchema(many=True), code=200)
    @decorators.catch_errors()
    @decorators.auth.required()
    def get(self):

        user = self.get_current_user()

        tokens = self.auth.get_tokens(user=user)

        return self.response(tokens)

    # token_id = uuid associated to the token you want to select
    @decorators.catch_errors()
    @decorators.auth.required()
    def delete(self, token_id):

        user = self.get_current_user()
        tokens = self.auth.get_tokens(user=user)

        for token in tokens:
            if token["id"] != token_id:
                continue
            if not self.auth.invalidate_token(token=token["token"]):
                raise RestApiException(
                    "Failed token invalidation: '{}'".format(token),
                    status_code=400
                )
            return self.empty_response()

        raise RestApiException(
            "Token not emitted for your account or does not exist",
            status_code=401
        )
