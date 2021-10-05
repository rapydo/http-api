from typing import Any, Dict

from restapi import decorators
from restapi.endpoints.schemas import TokenSchema
from restapi.exceptions import BadRequest, Forbidden
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import User

# from restapi.utilities.logs import log


def inject_token(
    endpoint: EndpointResource, token_id: str, user: User
) -> Dict[str, Any]:

    tokens = endpoint.auth.get_tokens(user=user)

    for token in tokens:
        if token["id"] == token_id:
            return {"token": token["token"]}

    raise Forbidden("Token not emitted for your account or does not exist")


class Tokens(EndpointResource):
    """List all active tokens for a user"""

    depends_on = ["AUTH_ENABLE"]
    labels = ["authentication"]

    @decorators.auth.require()
    @decorators.marshal_with(TokenSchema(many=True), code=200)
    @decorators.endpoint(
        path="/auth/tokens",
        summary="Retrieve all tokens emitted for logged user",
        responses={200: "List of tokens"},
    )
    def get(self, user: User) -> Response:

        tokens = self.auth.get_tokens(user=user)

        return self.response(tokens)

    # token_id = uuid associated to the token you want to select
    @decorators.auth.require()
    @decorators.preload(callback=inject_token)
    @decorators.endpoint(
        path="/auth/tokens/<token_id>",
        summary="Remove specified token and make it invalid from now on",
        responses={204: "Token has been invalidated"},
    )
    def delete(self, token_id: str, token: str, user: User) -> Response:

        if self.auth.invalidate_token(token=token):
            return self.empty_response()

        # Added just to make very sure, but it can never happen because
        # invalidate_token can only fail if the token is invalid
        # since this is an authenticated endpoint the token is already verified
        raise BadRequest(f"Failed token invalidation: {token}")  # pragma: no cover
