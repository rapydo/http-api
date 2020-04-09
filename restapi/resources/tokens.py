# -*- coding: utf-8 -*-

from flask import current_app
from restapi import decorators
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException

from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.logs import log


"""
class Tokens
    GET: get list of tokens for the current user
    DELETE: invalidate a token

class AdminTokens
    GET: get tokens for all users (admin only)

"""


class Tokens(EndpointResource):
    """ List all active tokens for a user """

    baseuri = "/auth"
    labels = ["authentication"]

    GET = {
        "/tokens": {
            "summary": "Retrieve all tokens emitted for logged user",
            "responses": {"200": {"description": "List of tokens"}},
        },
        "/tokens/<token_id>": {
            "summary": "Retrieve specified token if available for logged user",
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
            if not self.auth.invalidate_token(token=token["token"]):
                raise RestApiException(
                    "Failed token invalidation: '{}'".format(token),
                    status_code=hcodes.HTTP_BAD_REQUEST
                )
            return self.empty_response()

        raise RestApiException(
            "Token not emitted for your account or does not exist",
            status_code=hcodes.HTTP_BAD_UNAUTHORIZED
        )


class AdminTokens(EndpointResource):
    """ List all tokens for all users """

    labels = ["authentication"]

    GET = {
        "/admin/tokens": {
            "summary": "Retrieve all tokens emitted for logged user",
            "responses": {"200": {"description": "List of tokens"}},
        },
    }
    DELETE = {
        "/admin/tokens/<token_id>": {
            "summary": "Remove specified token and make it invalid from now on",
            "responses": {"200": {"description": "Token has been invalidated"}},
        },
    }

    @decorators.catch_errors()
    @decorators.auth.required(roles=['admin_root'])
    def get(self):

        users = {}
        tokens = self.auth.get_tokens(get_all=True)
        for idx, _ in enumerate(tokens):
            user_id = tokens[idx].pop('user_id')
            if user_id is None:
                log.warning("No user associated to token {}", tokens[idx])
                continue
            # Mongo directly provides the user
            if not isinstance(user_id, str):
                tokens[idx]['user_email'] = user_id.email
                tokens[idx]['user_name'] = user_id.name
                tokens[idx]['user_surname'] = user_id.surname

                continue

            # SQLAlchemy and neo4j provide the user_id
            if user_id not in users:
                u = self.auth.get_users(user_id=user_id).pop()

                users[user_id] = {
                    "user_email": u.email,
                    "user_name": u.name,
                    "user_surname": u.surname,
                }

            tokens[idx]['user_email'] = users[user_id].get("user_email")
            tokens[idx]['user_name'] = users[user_id].get("user_name")
            tokens[idx]['user_surname'] = users[user_id].get("user_surname")

        return self.response(tokens)

    # token_id = uuid associated to the token you want to select
    @decorators.catch_errors()
    @decorators.auth.required(roles=['admin_root'])
    def delete(self, token_id):
        """
            For additional security, tokens are invalidated both
            by changing the user UUID and by removing single tokens
        """
        try:
            tokens = self.auth.get_tokens(token_jti=token_id)
        except BaseException as e:
            log.error(e)
            tokens = None

        if not tokens:
            raise RestApiException(
                'This token does not exist',
                status_code=hcodes.HTTP_BAD_NOTFOUND
            )
        token = tokens[0]

        if not self.auth.invalidate_token(token=token["token"]):
            raise RestApiException(
                "Failed token invalidation: '{}'".format(token),
                status_code=hcodes.HTTP_BAD_REQUEST
            )
        return self.empty_response()
