from glom import glom

from restapi import decorators
from restapi.exceptions import BadRequest, NotFound
from restapi.models import Schema, fields
from restapi.resources.tokens import TokenSchema
from restapi.rest.definition import EndpointResource
from restapi.services.authentication import Role
from restapi.utilities.logs import log


class User(Schema):
    email = fields.Email()
    name = fields.Str()
    surname = fields.Str()


class TokenTotalSchema(Schema):
    total = fields.Int()


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

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.get_pagination
    @decorators.marshal_with(TokenAdminSchema(many=True), code=200)
    @decorators.marshal_with(TokenTotalSchema, code=206)
    def get(self, get_total, page, size, sort_by, sort_order, input_filter):

        tokens = self.auth.get_tokens(get_all=True)

        if input_filter:
            filtered_tokens = []
            for t in tokens:
                for f in ["token", "IP", "location", "user.email"]:
                    value = glom(t, f, default="").lower()
                    if input_filter in value:
                        filtered_tokens.append(t)
                        break

            tokens = filtered_tokens

        if get_total:
            return self.response({"total": len(tokens)}, code=206)

        if sort_by:
            tokens = sorted(
                tokens,
                key=lambda t: glom(t, sort_by, default=""),
                reverse=sort_order == "desc",
            )

        end = page * size
        start = end - size
        response = []
        for t in tokens[start:end]:
            if t.get("user") is None:
                log.error("Found a token without any user assigned: {}", t["id"])
                continue
            response.append(t)

        return self.response(response)

    @decorators.auth.require_all(Role.ADMIN)
    def delete(self, token_id):

        tokens = self.auth.get_tokens(token_jti=token_id)

        if not tokens:
            raise NotFound("This token does not exist")
        token = tokens[0]

        if not self.auth.invalidate_token(token=token["token"]):
            raise BadRequest(f"Failed token invalidation: '{token}'")
        return self.empty_response()
