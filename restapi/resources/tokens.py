# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from flask_apispec import marshal_with
from marshmallow import fields
from restapi.models import Schema
from restapi import decorators
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException

from restapi.utilities.logs import log


"""
class Tokens
    GET: get list of tokens for the current user
    DELETE: invalidate a token

class AdminTokens
    GET: get tokens for all users (admin only)

"""


class TokenSchema(Schema):
    id = fields.Str()
    IP = fields.Str()
    location = fields.Str()
    token = fields.Str()
    emitted = fields.DateTime()
    expiration = fields.DateTime()
    last_access = fields.DateTime()


class User(Schema):
    email = fields.Email()
    name = fields.Str()
    surname = fields.Str()


class TokenAdminSchema(TokenSchema):
    # token_type = fields.Str()
    user = fields.Nested(User)


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

        response = []
        tokens = self.auth.get_tokens(user=user)
        for t in tokens:
            if t['user'] is None:
                log.error(
                    "Found a token without any user assigned: {}",
                    t['id']
                )
                continue
            response.append(t)

        return self.response(response)

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


class AdminTokens(MethodResource, EndpointResource):
    """ List all tokens for all users """

    labels = ["authentication"]

    _GET = {
        "/admin/tokens": {
            "summary": "Retrieve all tokens emitted for logged user",
            "responses": {"200": {"description": "List of tokens"}},
        },
    }
    _DELETE = {
        "/admin/tokens/<token_id>": {
            "summary": "Remove specified token and make it invalid from now on",
            "responses": {"200": {"description": "Token has been invalidated"}},
        },
    }

    @marshal_with(TokenAdminSchema(many=True), code=200)
    @decorators.catch_errors()
    @decorators.auth.required(roles=['admin_root'])
    def get(self):

        tokens = self.auth.get_tokens(get_all=True)

        return self.response(tokens)

    @decorators.catch_errors()
    @decorators.auth.required(roles=['admin_root'])
    def delete(self, token_id):

        try:
            tokens = self.auth.get_tokens(token_jti=token_id)
        except BaseException as e:
            log.error(e)
            tokens = None

        if not tokens:
            raise RestApiException(
                'This token does not exist',
                status_code=404
            )
        token = tokens[0]

        if not self.auth.invalidate_token(token=token["token"]):
            raise RestApiException(
                "Failed token invalidation: '{}'".format(token),
                status_code=400
            )
        return self.empty_response()
