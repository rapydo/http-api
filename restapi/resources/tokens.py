# -*- coding: utf-8 -*-

from flask import current_app
from restapi import decorators
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException

from restapi.utilities.htmlcodes import hcodes

"""
class Tokens
    GET: get list of tokens for the current link
    DELETE: invalidate a token

"""


class Tokens(EndpointResource):
    """ List all active tokens for a user """

    baseuri = "/auth"
    labels = ["authentication"]

    GET = {
        "/tokens": {
            "summary": "Show all tokens emitted for logged user",
            "responses": {"200": {"description": "List of tokens"}},
        },
        "/tokens/<token_id>": {
            "summary": "Show specified token if available for logged user",
            "responses": {"200": {"description": "Details on the specified token"}},
        },
    }
    DELETE = {
        "/tokens": {
            "summary": "Remove all tokens emitted for a user",
            "description": "Note: only allowed for testing",
            "responses": {"200": {"description": "All tokens have been invalidated"}},
        },
        "/tokens/<token_id>": {
            "summary": "Remove specified token and make it invalid from now on",
            "responses": {"200": {"description": "Token has been invalidated"}},
        },
    }

    # token_id = uuid associated to the token you want to select
    @decorators.catch_errors()
    @decorators.auth.required()
    def get(self, token_id=None):

        user = self.get_current_user()

        tokens = self.auth.get_tokens(user=user)
        if token_id is None:
            return self.response(tokens)

        for token in tokens:
            if token["id"] == token_id:
                return self.response(token)

        raise RestApiException(
            'This token was not emitted for your account or it does not exist',
            status_code=hcodes.HTTP_BAD_NOTFOUND
        )

    # token_id = uuid associated to the token you want to select
    @decorators.catch_errors()
    @decorators.auth.required()
    def delete(self, token_id=None):
        """
            For additional security, tokens are invalidated both
            by changing the user UUID and by removing single tokens
        """

        user = self.get_current_user()

        if token_id is None:
            # NOTE: this is allowed only in removing tokens in unittests
            if not current_app.config['TESTING']:
                raise KeyError("TESTING IS FALSE! Specify a valid token")
            self.auth.invalidate_all_tokens(user=user)
            return self.empty_response()

        tokens = self.auth.get_tokens(user=user)

        for token in tokens:
            if token["id"] != token_id:
                continue
            if not self.auth.invalidate_token(token=token["token"], user=user):
                raise RestApiException(
                    "Failed token invalidation: '{}'".format(token),
                    status_code=hcodes.HTTP_BAD_REQUEST
                )
            return self.empty_response()

        raise RestApiException(
            "Token not emitted for your account or does not exist",
            status_code=hcodes.HTTP_BAD_UNAUTHORIZED
        )
