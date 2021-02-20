from glom import glom

from restapi import decorators
from restapi.endpoints.tokens import TokenSchema
from restapi.exceptions import BadRequest, NotFound
from restapi.models import Schema, TotalSchema, fields
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Role
from restapi.utilities.logs import log


class User(Schema):
    email = fields.Email()
    name = fields.Str()
    surname = fields.Str()


class TokenAdminSchema(TokenSchema):
    # token_type = fields.Str()
    user = fields.Nested(User)


class AdminTokens(EndpointResource):
    """ List all tokens for all users """

    labels = ["authentication"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.get_pagination
    @decorators.marshal_with(TokenAdminSchema(many=True), code=200)
    @decorators.marshal_with(TotalSchema, code=206)
    @decorators.endpoint(
        path="/admin/tokens",
        summary="Retrieve all tokens emitted for logged user",
        responses={
            200: "The list of tokens is returned",
            206: "Total number of elements is returned",
        },
    )
    def get(
        self,
        get_total: bool,
        page: int,
        size: int,
        sort_by: str,
        sort_order: str,
        input_filter: str,
    ) -> Response:

        tokens = self.auth.get_tokens(get_all=True)

        if input_filter:
            filtered_tokens = []
            for t in tokens:
                for f in ["token", "IP", "location", "user.email"]:
                    value = glom(t, f, default="")
                    if value and input_filter in value.lower():
                        filtered_tokens.append(t)
                        break

            tokens = filtered_tokens

        if get_total:
            return self.pagination_total(len(tokens))

        if sort_by:

            def sorter(t):
                return glom(t, sort_by, default="")

            tokens = sorted(
                tokens,
                # Raising error:
                # Returning Any from function declared to return "_SupportsLessThan"
                # https://github.com/python/mypy/issues/9656
                key=sorter,
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
    @decorators.endpoint(
        path="/admin/tokens/<token_id>",
        summary="Remove specified token and make it invalid from now on",
        responses={
            204: "Token has been invalidated",
            404: "Specified token cannot be found",
            400: "Token invalidation is failed",
        },
    )
    def delete(self, token_id: str) -> Response:

        tokens = self.auth.get_tokens(token_jti=token_id)

        if not tokens:
            raise NotFound("This token does not exist")
        token = tokens[0]

        if not self.auth.invalidate_token(token=token["token"]):
            raise BadRequest(f"Failed token invalidation: '{token}'")
        return self.empty_response()
