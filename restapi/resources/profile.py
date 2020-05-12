# -*- coding: utf-8 -*-

from restapi.rest.definition import EndpointResource
from restapi import decorators
from restapi.exceptions import RestApiException
from restapi.connectors.authentication import HandleSecurity
from restapi.utilities.meta import Meta
from restapi.utilities.logs import log


class Profile(EndpointResource):
    """ Current user informations """

    baseuri = "/auth"
    depends_on = ["not PROFILE_DISABLED"]
    labels = ["profile"]

    GET = {
        "/profile": {
            "summary": "List profile attributes",
            "responses": {
                "200": {"description": "Dictionary with all profile attributes"}
            },
        }
    }
    PUT = {
        "/profile": {
            "summary": "Update profile attributes",
            "parameters": [
                {
                    "name": "credentials",
                    "in": "body",
                    "schema": {"$ref": "#/definitions/ProfileUpdate"},
                }
            ],
            "responses": {"204": {"description": "Updated has been successful"}},
        }
    }

    @decorators.catch_errors()
    @decorators.auth.required()
    def get(self):

        current_user = self.get_current_user()
        data = {
            'uuid': current_user.uuid,
            'status': "Valid user",
            'email': current_user.email,
        }

        # roles = []
        roles = {}
        for role in current_user.roles:
            # roles.append(role.name)
            roles[role.name] = role.description
        data["roles"] = roles

        try:
            for g in current_user.belongs_to.all():
                data["group"] = {
                    "uuid": g.uuid,
                    "shortname": g.shortname,
                    "fullname": g.fullname,
                }
        except BaseException as e:
            log.verbose(e)

        data["isAdmin"] = self.auth.verify_admin()
        data["isLocalAdmin"] = self.auth.verify_local_admin()
        data["privacy_accepted"] = current_user.privacy_accepted

        if hasattr(current_user, 'name'):
            data["name"] = current_user.name

        if hasattr(current_user, 'surname'):
            data["surname"] = current_user.surname

        if self.auth.SECOND_FACTOR_AUTHENTICATION:
            data['2fa'] = self.auth.SECOND_FACTOR_AUTHENTICATION

        obj = Meta.get_customizer_class('apis.profile', 'CustomProfile')
        if obj is not None:
            try:
                data = obj.manipulate(ref=self, user=current_user, data=data)
            except BaseException as e:
                log.error("Could not custom manipulate profile:\n{}", e)

        return self.response(data)

    def update_password(self, user, data):

        password = data.get('password')
        new_password = data.get('new_password')
        password_confirm = data.get('password_confirm')

        totp_authentication = self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP

        if totp_authentication:
            totp_code = data.get('totp_code')
        else:
            totp_code = None

        security = HandleSecurity(self.auth)

        if new_password is None or password_confirm is None:
            msg = "New password is missing"
            raise RestApiException(msg, status_code=400)

        if totp_authentication:
            security.verify_totp(user, totp_code)
        else:
            token, _ = self.auth.make_login(user.email, password)
            security.verify_token(user.email, token)

        security.change_password(user, password, new_password, password_confirm)

        # NOTE already in change_password
        # but if removed new pwd is not saved
        return self.auth.save_user(user)

    def update_profile(self, user, data):

        avoid_update = ['uuid', 'authmethod', 'is_active', 'roles']

        try:
            for key, value in data.items():
                if key.startswith('_') or key in avoid_update:
                    continue
                log.debug("Profile new value: {}={}", key, value)
                setattr(user, key, value)
        except BaseException as e:
            log.error("Failed to update profile:\n{}: {}", e.__class__.__name__, e)
        else:
            log.info("Profile updated")

        self.auth.save_user(user)

    @decorators.catch_errors()
    @decorators.auth.required()
    def put(self):
        """ Update profile for current user """

        user = self.auth.get_user()
        data = self.get_input()

        if 'password' in data:
            self.update_password(user, data)
            return self.empty_response()

        self.update_profile(user, data)

        return self.empty_response()
