from flask_apispec import MethodResource, marshal_with
from marshmallow import fields

from restapi import decorators
from restapi.exceptions import BadRequest, Unauthorized
from restapi.models import OutputSchema
from restapi.rest.definition import EndpointResource

# from restapi.utilities.logs import log


class TokenSchema(OutputSchema):
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

        user = self.get_user()

        tokens = self.auth.get_tokens(user=user)

        return self.response(tokens)

    # token_id = uuid associated to the token you want to select
    @decorators.catch_errors()
    @decorators.auth.required()
    def delete(self, token_id):

        user = self.get_user()
        tokens = self.auth.get_tokens(user=user)

        for token in tokens:
            if token["id"] != token_id:
                continue

            if self.auth.invalidate_token(token=token["token"]):
                return self.empty_response()

            # Added just to make very sure, but it can never happen because
            # invalidate_token can only fail if the token is invalid
            # since this is an authenticated endpoint the token is already verified
            raise BadRequest(f"Failed token invalidation: {token}")  # pragma: no cover

        raise Unauthorized("Token not emitted for your account or does not exist")
