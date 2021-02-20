from typing import Any, Optional

from restapi import decorators
from restapi.connectors import Connector
from restapi.endpoints.schemas import NewPassword, profile_output, profile_patch_input
from restapi.rest.definition import EndpointResource, Response
from restapi.utilities.globals import mem
from restapi.utilities.logs import log


class Profile(EndpointResource):

    baseuri = "/auth"
    depends_on = ["MAIN_LOGIN_ENABLE"]
    labels = ["profile"]

    @decorators.auth.require()
    @decorators.marshal_with(profile_output(), code=200)
    @decorators.endpoint(
        path="/profile",
        summary="List profile attributes",
        responses={200: "User profile is returned"},
    )
    def get(self) -> Response:

        current_user = self.get_user()
        data = {
            "uuid": current_user.uuid,
            "email": current_user.email,
            "name": current_user.name,
            "surname": current_user.surname,
            "isAdmin": self.verify_admin(),
            "isStaff": self.verify_staff(),
            "isCoordinator": self.verify_coordinator(),
            "privacy_accepted": current_user.privacy_accepted,
            "last_password_change": current_user.last_password_change,
            "first_login": current_user.first_login,
            "last_login": current_user.last_login,
            "is_active": current_user.is_active,
            "expiration": current_user.expiration,
            # Convert list of Roles into a dict with name: description
            "roles": {role.name: role.description for role in current_user.roles},
        }

        # To be replaced with Neo4jRelationshipToSingle
        if Connector.authentication_service == "neo4j":
            data["group"] = current_user.belongs_to.single()
        else:
            data["group"] = current_user.belongs_to

        data["two_factor_enabled"] = self.auth.SECOND_FACTOR_AUTHENTICATION

        data = mem.customizer.manipulate_profile(ref=self, user=current_user, data=data)

        return self.response(data)

    @decorators.auth.require()
    @decorators.use_kwargs(NewPassword)
    @decorators.endpoint(
        path="/profile",
        summary="Update user password",
        responses={204: "Password updated"},
    )
    def put(
        self,
        password: str,
        new_password: str,
        password_confirm: str,
        totp_code: Optional[str] = None,
    ) -> Response:
        """ Update password for current user """

        user = self.get_user()

        if self.auth.SECOND_FACTOR_AUTHENTICATION:
            self.auth.verify_totp(user, totp_code)

        self.auth.make_login(user.email, password)

        self.auth.change_password(user, password, new_password, password_confirm)

        self.auth.save_user(user)

        return self.empty_response()

    @decorators.auth.require()
    @decorators.use_kwargs(profile_patch_input())
    @decorators.endpoint(
        path="/profile",
        summary="Update profile information",
        responses={204: "Profile updated"},
    )
    def patch(self, **kwargs: Any) -> Response:
        """ Update profile for current user """

        user = self.get_user()

        self.auth.db.update_properties(user, kwargs)

        log.info("Profile updated")

        self.auth.save_user(user)

        self.log_event(self.events.modify, user, kwargs)
        return self.empty_response()
