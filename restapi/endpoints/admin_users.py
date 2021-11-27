from typing import Any, Dict, List

from restapi import decorators
from restapi.connectors.smtp.notifications import (
    notify_new_credentials_to_user,
    notify_update_credentials_to_user,
)
from restapi.endpoints.schemas import (
    admin_user_output,
    admin_user_post_input,
    admin_user_put_input,
)
from restapi.exceptions import NotFound
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import BaseAuthentication, Role, User
from restapi.utilities.time import date_lower_than as dt_lower

# from restapi.utilities.logs import log


def inject_user(endpoint: EndpointResource, user_id: str) -> Dict[str, Any]:

    user = endpoint.auth.get_user(user_id=user_id)
    if user is None:
        raise NotFound("This user cannot be found or you are not authorized")

    return {"target_user": user}


class AdminSingleUser(EndpointResource):
    depends_on = ["MAIN_LOGIN_ENABLE", "AUTH_ENABLE"]
    labels = ["admin"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.preload(callback=inject_user)
    @decorators.marshal_with(admin_user_output(many=False), code=200)
    @decorators.endpoint(
        path="/admin/users/<user_id>",
        summary="Return information on a single user",
        responses={200: "User information successfully retrieved"},
    )
    def get(self, user_id: str, target_user: User, user: User) -> Response:

        self.log_event(self.events.access, target_user)

        return self.response(target_user)


class AdminUsers(EndpointResource):

    depends_on = ["MAIN_LOGIN_ENABLE", "AUTH_ENABLE"]
    labels = ["admin"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.marshal_with(admin_user_output(many=True), code=200)
    @decorators.endpoint(
        path="/admin/users",
        summary="Return the list of all defined users",
        responses={200: "List of users successfully retrieved"},
    )
    def get(self, user: User) -> Response:

        users = self.auth.get_users()

        return self.response(users)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.database_transaction
    @decorators.use_kwargs(admin_user_post_input)
    @decorators.endpoint(
        path="/admin/users",
        summary="Create a new user",
        responses={
            200: "The uuid of the new user is returned",
            409: "This user already exists",
        },
    )
    def post(self, user: User, **kwargs: Any) -> Response:

        roles: List[str] = kwargs.pop("roles", [])
        payload = kwargs.copy()
        group_id = kwargs.pop("group")

        email_notification = kwargs.pop("email_notification", False)

        unhashed_password = kwargs["password"]

        # If created by admins users must accept privacy at first login
        kwargs["privacy_accepted"] = False

        user = self.auth.create_user(kwargs, roles)
        self.auth.save_user(user)

        group = self.auth.get_group(group_id=group_id)
        if not group:
            # Can't be reached because group_id is prefiltered by marshmallow
            raise NotFound("This group cannot be found")  # pragma: no cover

        self.auth.add_user_to_group(user, group)

        if email_notification and unhashed_password is not None:
            notify_new_credentials_to_user(user, unhashed_password)

        self.log_event(self.events.create, user, payload)

        return self.response(user.uuid)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.preload(callback=inject_user)
    @decorators.database_transaction
    @decorators.use_kwargs(admin_user_put_input)
    @decorators.endpoint(
        path="/admin/users/<user_id>",
        summary="Modify a user",
        responses={200: "User successfully modified"},
    )
    def put(
        self, user_id: str, target_user: User, user: User, **kwargs: Any
    ) -> Response:

        if "password" in kwargs:
            unhashed_password = kwargs["password"]
            kwargs["password"] = BaseAuthentication.get_password_hash(
                kwargs["password"]
            )
        else:
            unhashed_password = None

        payload = kwargs.copy()
        roles: List[str] = kwargs.pop("roles", [])

        group_id = kwargs.pop("group", None)

        email_notification = kwargs.pop("email_notification", False)

        self.auth.link_roles(target_user, roles)

        userdata, extra_userdata = self.auth.custom_user_properties_pre(kwargs)

        prev_expiration = target_user.expiration

        # mypy correctly raises errors because update_properties is not defined
        # in generic Connector instances, but in this case this is an instance
        # of an auth db and their implementation always contains this method
        self.auth.db.update_properties(target_user, userdata)  # type: ignore

        self.auth.custom_user_properties_post(
            target_user, userdata, extra_userdata, self.auth.db
        )

        self.auth.save_user(target_user)

        if group_id is not None:
            group = self.auth.get_group(group_id=group_id)
            if not group:
                # Can't be reached because group_id is prefiltered by marshmallow
                raise NotFound("This group cannot be found")  # pragma: no cover

            self.auth.add_user_to_group(target_user, group)

        if email_notification and unhashed_password is not None:
            notify_update_credentials_to_user(target_user, unhashed_password)

        if target_user.expiration:
            # Set expiration on a previously non-expiring account
            # or update the expiration by reducing the validity period
            # In both cases tokens should be invalited to prevent to have tokens
            # with TTL > account validity

            # dt_lower (alias for date_lower_than) is a comparison fn that ignores tz
            if not prev_expiration or dt_lower(target_user.expiration, prev_expiration):
                for token in self.auth.get_tokens(user=target_user):
                    # Invalidate all tokens with expiration after the account expiration
                    if dt_lower(target_user.expiration, token["expiration"]):
                        self.auth.invalidate_token(token=token["token"])

        self.log_event(self.events.modify, target_user, payload)

        return self.empty_response()

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.preload(callback=inject_user)
    @decorators.endpoint(
        path="/admin/users/<user_id>",
        summary="Delete a user",
        responses={200: "User successfully deleted"},
    )
    def delete(self, user_id: str, target_user: User, user: User) -> Response:

        self.auth.delete_user(target_user)

        self.log_event(self.events.delete, target_user)

        return self.empty_response()
