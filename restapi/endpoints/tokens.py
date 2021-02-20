from restapi import decorators
from restapi.exceptions import BadRequest, Forbidden
from restapi.models import ISO8601UTC, Schema, fields
from restapi.rest.definition import EndpointResource, Response

# from restapi.utilities.logs import log


class TokenSchema(Schema):
    id = fields.Str()
    IP = fields.Str()
    location = fields.Str()
    token = fields.Str()
    emitted = fields.DateTime(format=ISO8601UTC)
    expiration = fields.DateTime(format=ISO8601UTC)
    last_access = fields.DateTime(format=ISO8601UTC)


class Tokens(EndpointResource):
    """ List all active tokens for a user """

    baseuri = "/auth"
    labels = ["authentication"]

    @decorators.auth.require()
    @decorators.marshal_with(TokenSchema(many=True), code=200)
    @decorators.endpoint(
        path="/tokens",
        summary="Retrieve all tokens emitted for logged user",
        responses={200: "List of tokens"},
    )
    def get(self) -> Response:

        user = self.get_user()

        tokens = self.auth.get_tokens(user=user)

        return self.response(tokens)

    # token_id = uuid associated to the token you want to select
    @decorators.auth.require()
    @decorators.endpoint(
        path="/tokens/<token_id>",
        summary="Remove specified token and make it invalid from now on",
        responses={204: "Token has been invalidated"},
    )
    def delete(self, token_id: str) -> Response:

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

        raise Forbidden("Token not emitted for your account or does not exist")
