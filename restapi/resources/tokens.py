# -*- coding: utf-8 -*-

from flask import current_app
from restapi.rest.definition import EndpointResource

from utilities import htmlcodes as hcodes

"""
class Tokens
    GET: get list of tokens for the current link
    DELETE: invalidate a token

"""


class Tokens(EndpointResource):
    """ List all active tokens for a user """

    def get_user(self):

        iamadmin = self.auth.verify_admin()

        if iamadmin:
            username = self.get_input(single_parameter='username')
            if username is not None:
                username = username.lower()
                return self.auth.get_user_object(username=username)

        return self.get_current_user()

    def get(self, token_id=None):

        user = self.get_user()
        if user is None:
            return self.send_errors(
                message="Invalid: bad username", code=hcodes.HTTP_BAD_REQUEST)

        tokens = self.auth.get_tokens(user=user)
        if token_id is None:
            return tokens

        for token in tokens:
            if token["id"] == token_id:
                return token

        errorMessage = """Either this token was not emitted for your account
                          or it does not exist"""

        return self.send_errors(
            message=errorMessage, code=hcodes.HTTP_BAD_NOTFOUND)

    def delete(self, token_id=None):
        """
            For additional security, tokens are invalidated both
            by chanding the user UUID and by removing single tokens
        """

        user = self.get_user()
        if user is None:
            return self.send_errors(
                message="Invalid: bad username", code=hcodes.HTTP_BAD_REQUEST)

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
                    code=hcodes.HTTP_BAD_REQUEST)
            return self.empty_response()

        message = "Token not emitted for your account or does not exist"
        return self.send_errors(
            message=message, code=hcodes.HTTP_BAD_UNAUTHORIZED)
