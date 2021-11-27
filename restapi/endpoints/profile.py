from typing import Any, Optional

from restapi import decorators
from restapi.endpoints.schemas import NewPassword, profile_output, profile_patch_input
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import User
from restapi.utilities.globals import mem
from restapi.utilities.logs import log


class Profile(EndpointResource):

    depends_on = ["MAIN_LOGIN_ENABLE", "AUTH_ENABLE"]
    labels = ["profile"]

    @decorators.auth.require()
    @decorators.marshal_with(profile_output(), code=200)
    @decorators.endpoint(
        path="/auth/profile",
        summary="List profile attributes",
        responses={200: "User profile is returned"},
    )
    def get(self, user: User) -> Response:

        data = {
            "uuid": user.uuid,
            "email": user.email,
            "name": user.name,
            "surname": user.surname,
            "isAdmin": self.auth.is_admin(user),
            "isStaff": self.auth.is_staff(user),
            "isCoordinator": self.auth.is_coordinator(user),
            "privacy_accepted": user.privacy_accepted,
            "last_password_change": user.last_password_change,
            "first_login": user.first_login,
            "last_login": user.last_login,
            "is_active": user.is_active,
            "expiration": user.expiration,
            "belongs_to": user.belongs_to,
            # Convert list of Roles into a dict with name: description
            "roles": {role.name: role.description for role in user.roles},
            "two_factor_enabled": self.auth.SECOND_FACTOR_AUTHENTICATION,
        }

        data = mem.customizer.manipulate_profile(ref=self, user=user, data=data)

        return self.response(data)

    @decorators.auth.require()
    @decorators.use_kwargs(NewPassword)
    @decorators.endpoint(
        path="/auth/profile",
        summary="Update user password",
        responses={204: "Password updated"},
    )
    def put(
        self,
        password: str,
        new_password: str,
        password_confirm: str,
        user: User,
        totp_code: Optional[str] = None,
    ) -> Response:
        """Update password for current user"""
        if self.auth.SECOND_FACTOR_AUTHENTICATION:
            self.auth.verify_totp(user, totp_code)

        self.auth.make_login(user.email, password)

        self.auth.change_password(user, password, new_password, password_confirm)

        self.auth.save_user(user)

        return self.empty_response()

    @decorators.auth.require()
    @decorators.use_kwargs(profile_patch_input())
    @decorators.endpoint(
        path="/auth/profile",
        summary="Update profile information",
        responses={204: "Profile updated"},
    )
    def patch(self, user: User, **kwargs: Any) -> Response:
        """Update profile for current user"""

        # mypy correctly raises errors because update_properties is not defined
        # in generic Connector instances, but in this case this is an instance
        # of an auth db and their implementation always contains this method
        self.auth.db.update_properties(user, kwargs)  # type: ignore

        log.info("Profile updated")

        self.auth.save_user(user)

        self.log_event(self.events.modify, user, kwargs)
        return self.empty_response()
