from restapi import decorators
from restapi.exceptions import RestApiException
from restapi.models import OutputSchema, fields
from restapi.resources.tokens import TokenSchema
from restapi.rest.definition import EndpointResource
from restapi.utilities.logs import log


class User(OutputSchema):
    email = fields.Email()
    name = fields.Str()
    surname = fields.Str()


class TokenAdminSchema(TokenSchema):
    # token_type = fields.Str()
    user = fields.Nested(User)


class AdminTokens(EndpointResource):
    """ List all tokens for all users """

    labels = ["authentication"]

    _GET = {
        "/admin/tokens": {
            "private": True,
            "summary": "Retrieve all tokens emitted for logged user",
            "responses": {"200": {"description": "List of tokens"}},
        },
    }
    _DELETE = {
        "/admin/tokens/<token_id>": {
            "private": True,
            "summary": "Remove specified token and make it invalid from now on",
            "responses": {"200": {"description": "Token has been invalidated"}},
        },
    }

    @decorators.auth.require_all("admin_root")
    @decorators.marshal_with(TokenAdminSchema(many=True), code=200)
    def get(self):

        tokens = self.auth.get_tokens(get_all=True)

        response = []
        for t in tokens:
            if t.get("user") is None:
                log.error("Found a token without any user assigned: {}", t["id"])
                continue
            response.append(t)

        return self.response(response)

    @decorators.auth.require_all("admin_root")
    def delete(self, token_id):

        tokens = self.auth.get_tokens(token_jti=token_id)

        if not tokens:
            raise RestApiException("This token does not exist", status_code=404)
        token = tokens[0]

        if not self.auth.invalidate_token(token=token["token"]):
            raise RestApiException(
                f"Failed token invalidation: '{token}'", status_code=400
            )
        return self.empty_response()
