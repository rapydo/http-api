# -*- coding: utf-8 -*-

from flask import current_app
from restapi.rest.definition import EndpointResource
from restapi.protocols.bearer import authentication

from utilities import htmlcodes as hcodes

"""
class Tokens
    GET: get list of tokens for the current link
    DELETE: invalidate a token

"""


class Tokens(EndpointResource):
    """ List all active tokens for a user """

    baseuri = "/auth"
    labels = ["authentication"]

    SPECS = {
        "mapping": {
            "tokenizers": "/tokens",
            "tokenizer": "/tokens/<token_id>"
        },
        "ids": {
            "token_id": "uuid associated to the token you want to select"
        }
    }
    GET = {
        "tokenizers": {
            "summary": "Show all tokens emitted for logged user",
            "custom": {
                "publish": True,
            },
            "responses": {
                "200": {
                    "description": "List of tokens"
                }
            }
        },
        "tokenizer": {
            "summary": "Show specified token if available for logged user",
            "custom": {
                "publish": True,
            },
            "responses": {
                "200": {
                    "description": "Details on the specified token"
                }
            }
        }
    }
    DELETE = {
        "tokenizers": {
            "summary": "Remove all tokens emitted for logged user",
            "description": "Note: allowed only for testing",
            "responses": {
                "200": {
                    "description": "Tokens have been erased"
                }
            }
        },
        "tokenizer": {
            "summary": "Remove specified token and make it invalid from now on",
            "responses": {
                "200": {
                    "description": "Token has been invalidated"
                }
            }
        }
    }
    def get_user(self):

        iamadmin = self.auth.verify_admin()

        if iamadmin:
            username = self.get_input(single_parameter='username')
            if username is not None:
                username = username.lower()
                return self.auth.get_user_object(username=username)

        return self.get_current_user()

    @authentication.required()
    def get(self, token_id=None):

        user = self.get_user()
        if user is None:
            return self.send_errors(
                message="Invalid: bad username", code=hcodes.HTTP_BAD_REQUEST
            )

        tokens = self.auth.get_tokens(user=user)
        if token_id is None:
            return tokens

        for token in tokens:
            if token["id"] == token_id:
                return token

        errorMessage = """Either this token was not emitted for your account
                          or it does not exist"""

        return self.send_errors(message=errorMessage, code=hcodes.HTTP_BAD_NOTFOUND)

    @authentication.required()
    def delete(self, token_id=None):
        """
            For additional security, tokens are invalidated both
            by chanding the user UUID and by removing single tokens
        """

        user = self.get_user()
        if user is None:
            return self.send_errors(
                message="Invalid: bad username", code=hcodes.HTTP_BAD_REQUEST
            )

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
                return self.send_errors(
                    message="Failed token invalidation: '%s'" % token,
                    code=hcodes.HTTP_BAD_REQUEST,
                )
            return self.empty_response()

        message = "Token not emitted for your account or does not exist"
        return self.send_errors(message=message, code=hcodes.HTTP_BAD_UNAUTHORIZED)
