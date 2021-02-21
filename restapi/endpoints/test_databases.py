from restapi import decorators
from restapi.config import TESTING
from restapi.connectors import Connector
from restapi.exceptions import DatabaseDuplicatedEntry
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import DEFAULT_GROUP_NAME

# from restapi.utilities.logs import log

if TESTING:

    # This endpoint will try to create database object with unique keys
    # A duplicated entry exception will be raised and catched by the
    # database_transaction that will restore previous modifications
    class TestDatabase(EndpointResource):

        labels = ["tests"]

        @decorators.database_transaction
        @decorators.endpoint(
            path="/tests/database/<data>",
            summary="Execute tests on database functionalities",
            description="Only enabled in testing mode",
            responses={
                200: "Tests executed",
                400: "Bad input",
                409: "Group already exists",
            },
        )
        def post(self, data: str) -> Response:

            # Special value! This will try to create a group without shortname
            # A BadRequest will be raised due to the missing property
            if data == "400":
                from restapi.utilities.logs import log

                log.error("Debug code! data == '400'")
                group = self.auth.create_group({"fullname": data})
                self.auth.save_group(group)
                return self.response("0")

            # Only DatabaseDuplicatedEntry will be raised by this endpoint
            # Any other exceptions will be suppressed. This will ensure that
            # DatabaseDuplicatedEntry is raised and no others.
            # As a side effect this endpoint will modifiy the fullname of the default
            # Group if the exception is not raised. Otherwise this modification will
            # be undo by the database_transaction decorator
            try:

                default_group = self.auth.get_group(name=DEFAULT_GROUP_NAME)

                default_group.fullname = f"{default_group.fullname}_exteded"
                # Don't commit with alchemy or the transaction can't be rollbacked
                if Connector.authentication_service != "sqlalchemy":
                    self.auth.save_group(default_group)

                # This can fail if data is a duplicate of a already created group
                # In this case a DatabaseDuplicatedEntry excepton will be raised and the
                # database_transaction decorator will undo the change on the default grp
                group = self.auth.create_group({"shortname": data, "fullname": data})
                # Don't commit with alchemy or the transaction can't be rollbacked
                if Connector.authentication_service != "sqlalchemy":
                    self.auth.save_group(group)

                return self.response("1")
            except DatabaseDuplicatedEntry:
                raise
            except BaseException:  # pragma: no cover
                return self.response("0")
