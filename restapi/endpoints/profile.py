from typing import Any, Optional

from restapi import decorators
from restapi.endpoints.schemas import NewPassword, profile_output, profile_patch_input
from restapi.exceptions import ServiceUnavailable
from restapi.rest.definition import EndpointResource, Response
from restapi.utilities.globals import mem
from restapi.utilities.logs import log


class Profile(EndpointResource):

    depends_on = ["MAIN_LOGIN_ENABLE"]
    labels = ["profile"]

    @decorators.auth.require()
    @decorators.marshal_with(profile_output(), code=200)
    @decorators.endpoint(
        path="/auth/profile",
        summary="List profile attributes",
        responses={200: "User profile is returned"},
    )
    def get(self) -> Response:

        user = self.get_user()

        # Can't happen since auth is required
        if user is None:  # pragma: no cover
            raise ServiceUnavailable("Unexpected internal error")

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
        totp_code: Optional[str] = None,
    ) -> Response:
        """ Update password for current user """

        user = self.get_user()

        # Can't happen since auth is required
        if user is None:  # pragma: no cover
            raise ServiceUnavailable("Unexpected internal error")

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
    def patch(self, **kwargs: Any) -> Response:
        """ Update profile for current user """

        user = self.get_user()

        self.auth.db.update_properties(user, kwargs)

        log.info("Profile updated")

        self.auth.save_user(user)

        self.log_event(self.events.modify, user, kwargs)
        return self.empty_response()
