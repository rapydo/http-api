import re
from typing import Dict, List, Optional

import pytest

from restapi.config import ABS_RESTAPI_PATH
from restapi.connectors import Connector
from restapi.env import Env
from restapi.rest.loader import EndpointsLoader
from restapi.services.authentication import Role
from restapi.tests import SERVER_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log


class TestApp1(BaseTests):
    @staticmethod
    def get_path(method: str, path: str) -> str:
        method = method.upper()
        path = re.sub(r"\{[a-zA-Z0-9_]+\}", "VARIABLE", path)
        path = re.sub(r"\<[a-zA-Z0-9_]+\>", "VARIABLE", path)
        return f"{method} {path}"

    # This utility returns a list of _core_ paths with the form:
    # METHOD /path, e.g.
    # GET /api/admin/users
    # POST /api/admin/users
    def get_paths(self, client: FlaskClient) -> List[str]:

        loader = EndpointsLoader()
        loader.load_endpoints_folder(ABS_RESTAPI_PATH)

        paths: List[str] = []
        for endpoint_class in loader.endpoints:
            for method, paths_list in endpoint_class.methods.items():
                for path in paths_list:

                    if path.startswith("/api/tests/"):
                        continue

                    p = self.get_path(method, path)
                    log.warning("DEBUG CODE: Loaded endpoint {}", p)
                    paths.append(p)

        return paths

    # Test a single endpoint, remove the path from the list and return the new list
    # Once tested all paths, the list should be empty
    def check_endpoint(
        self,
        client: FlaskClient,
        method: str,
        endpoint: str,
        headers: Optional[Dict[str, str]],
        expected_authorized: bool,
        paths: List[str],
    ) -> List[str]:

        assert method in (
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        )

        path = self.get_path(method, endpoint)

        assert path in paths

        # SERVER_URI because api and auth are already included in endpoint
        full_endpoint = f"{SERVER_URI}/{endpoint}"

        if method == "GET":
            r = client.get(full_endpoint, headers=headers)
        elif method == "POST":
            r = client.post(full_endpoint, headers=headers)
        elif method == "PUT":
            r = client.put(full_endpoint, headers=headers)
        elif method == "PATCH":
            r = client.patch(full_endpoint, headers=headers)
        elif method == "DELETE":
            r = client.delete(full_endpoint, headers=headers)
        else:  # pragma: no cover
            pytest.fail("Unknown method")

        if expected_authorized:
            assert r.status_code != 401
        else:
            assert r.status_code != 400

        paths.remove(path)
        return paths

    def test_admin(self, client: FlaskClient) -> None:

        # List of all paths to be tested. After each test a path will be removed.
        # At the end the list is expected to be empty
        paths = self.get_paths(client)

        uuid, data = self.create_user(client, roles=[Role.ADMIN])
        headers, user_token = self.do_login(
            client, data.get("email"), data.get("password")
        )

        # These are public
        paths = self.check_endpoint(client, "GET", "/api/status", headers, True, paths)
        paths = self.check_endpoint(client, "GET", "/api/specs", headers, True, paths)
        paths = self.check_endpoint(client, "POST", "/auth/login", headers, True, paths)
        if Env.get_bool("ALLOW_REGISTRATION"):
            paths = self.check_endpoint(
                client, "POST", "/auth/profile", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "POST", "/auth/profile/activate", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/profile/activate/<token>", headers, True, paths
            )

        if Env.get_bool("ALLOW_PASSWORD_RESET") and Connector.check_availability(
            "smtp"
        ):
            paths = self.check_endpoint(
                client, "POST", "/auth/reset", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/reset/<token>", headers, True, paths
            )

        # These are allowed to each user
        paths = self.check_endpoint(client, "GET", "/auth/status", headers, True, paths)
        paths = self.check_endpoint(
            client, "GET", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PATCH", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(client, "GET", "/auth/tokens", headers, True, paths)
        paths = self.check_endpoint(
            client, "DELETE", "/auth/tokens/<token>", headers, True, paths
        )

        if Connector.check_availability("pushpin"):
            paths = self.check_endpoint(
                client, "PUT", "/api/socket/<channel>/<sync>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/socket/<channel>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "PUT", "/api/stream/<channel>/<sync>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/stream/<channel>", headers, True, paths
            )

        # These are allowed to coordinators
        # ... none

        # These are allowed to staff
        # ... none

        # These are allowed to admins
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users/<user_id>", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/users", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/users/<user_id>", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/users/<user_id>", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/groups", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/groups", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/groups/<group_id>", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/groups/<group_id>", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/tokens", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/tokens/<token>", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/stats", headers, True, paths
        )

        # logout MUST be the last one or the token will be invalidated!! :-)
        paths = self.check_endpoint(client, "GET", "/auth/logout", headers, True, paths)

        assert paths == []

        self.delete_user(client, uuid)

    def test_staff(self, client: FlaskClient) -> None:

        auth = Connector.get_authentication_instance()
        auth.get_roles()

        if "staff_user" not in [r.name for r in auth.get_roles()]:  # pragma: no cover
            log.warning("Skipping authorization tests on role Staff (not enabled)")
            return

        # List of all paths to be tested. After each test a path will be removed.
        # At the end the list is expected to be empty
        paths = self.get_paths(client)

        uuid, data = self.create_user(client, roles=[Role.STAFF])
        headers, user_token = self.do_login(
            client, data.get("email"), data.get("password")
        )

        # These are public
        paths = self.check_endpoint(client, "GET", "/api/status", headers, True, paths)
        paths = self.check_endpoint(client, "GET", "/api/specs", headers, True, paths)
        paths = self.check_endpoint(client, "POST", "/auth/login", headers, True, paths)
        if Env.get_bool("ALLOW_REGISTRATION"):
            paths = self.check_endpoint(
                client, "POST", "/auth/profile", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "POST", "/auth/profile/activate", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/profile/activate/<token>", headers, True, paths
            )

        if Env.get_bool("ALLOW_PASSWORD_RESET") and Connector.check_availability(
            "smtp"
        ):
            paths = self.check_endpoint(
                client, "POST", "/auth/reset", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/reset/<token>", headers, True, paths
            )

        # These are allowed to each user
        paths = self.check_endpoint(client, "GET", "/auth/status", headers, True, paths)
        paths = self.check_endpoint(
            client, "GET", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PATCH", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(client, "GET", "/auth/tokens", headers, True, paths)
        paths = self.check_endpoint(
            client, "DELETE", "/auth/tokens/<token>", headers, True, paths
        )

        if Connector.check_availability("pushpin"):
            paths = self.check_endpoint(
                client, "PUT", "/api/socket/<channel>/<sync>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/socket/<channel>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "PUT", "/api/stream/<channel>/<sync>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/stream/<channel>", headers, True, paths
            )

        # These are allowed to coordinators
        # ... none

        # These are allowed to staff
        # ... none

        # These are allowed to admins
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/users", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/groups", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/groups", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/groups/<group_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/groups/<group_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/tokens", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/tokens/<token>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/stats", headers, False, paths
        )

        # logout MUST be the last one or the token will be invalidated!! :-)
        paths = self.check_endpoint(client, "GET", "/auth/logout", headers, True, paths)

        assert paths == []

        self.delete_user(client, uuid)

    def test_coordinator(self, client: FlaskClient) -> None:
        # List of all paths to be tested. After each test a path will be removed.
        # At the end the list is expected to be empty
        paths = self.get_paths(client)

        uuid, data = self.create_user(client, roles=[Role.COORDINATOR])
        headers, user_token = self.do_login(
            client, data.get("email"), data.get("password")
        )

        # These are public
        paths = self.check_endpoint(client, "GET", "/api/status", headers, True, paths)
        paths = self.check_endpoint(client, "GET", "/api/specs", headers, True, paths)
        paths = self.check_endpoint(client, "POST", "/auth/login", headers, True, paths)
        if Env.get_bool("ALLOW_REGISTRATION"):
            paths = self.check_endpoint(
                client, "POST", "/auth/profile", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "POST", "/auth/profile/activate", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/profile/activate/<token>", headers, True, paths
            )

        if Env.get_bool("ALLOW_PASSWORD_RESET") and Connector.check_availability(
            "smtp"
        ):
            paths = self.check_endpoint(
                client, "POST", "/auth/reset", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/reset/<token>", headers, True, paths
            )

        # These are allowed to each user
        paths = self.check_endpoint(client, "GET", "/auth/status", headers, True, paths)
        paths = self.check_endpoint(
            client, "GET", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PATCH", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(client, "GET", "/auth/tokens", headers, True, paths)
        paths = self.check_endpoint(
            client, "DELETE", "/auth/tokens/<token>", headers, True, paths
        )

        if Connector.check_availability("pushpin"):
            paths = self.check_endpoint(
                client, "PUT", "/api/socket/<channel>/<sync>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/socket/<channel>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "PUT", "/api/stream/<channel>/<sync>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/stream/<channel>", headers, True, paths
            )

        # These are allowed to coordinators
        # ... none

        # These are allowed to staff
        # ... none

        # These are allowed to admins
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/users", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/groups", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/groups", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/groups/<group_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/groups/<group_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/tokens", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/tokens/<token>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/stats", headers, False, paths
        )

        # logout MUST be the last one or the token will be invalidated!! :-)
        paths = self.check_endpoint(client, "GET", "/auth/logout", headers, True, paths)

        assert paths == []

        self.delete_user(client, uuid)

    def test_user(self, client: FlaskClient) -> None:
        # List of all paths to be tested. After each test a path will be removed.
        # At the end the list is expected to be empty
        paths = self.get_paths(client)

        uuid, data = self.create_user(client, roles=[Role.USER])
        headers, user_token = self.do_login(
            client, data.get("email"), data.get("password")
        )

        # These are public
        paths = self.check_endpoint(client, "GET", "/api/status", headers, True, paths)
        paths = self.check_endpoint(client, "GET", "/api/specs", headers, True, paths)
        paths = self.check_endpoint(client, "POST", "/auth/login", headers, True, paths)
        if Env.get_bool("ALLOW_REGISTRATION"):
            paths = self.check_endpoint(
                client, "POST", "/auth/profile", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "POST", "/auth/profile/activate", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/profile/activate/<token>", headers, True, paths
            )

        if Env.get_bool("ALLOW_PASSWORD_RESET") and Connector.check_availability(
            "smtp"
        ):
            paths = self.check_endpoint(
                client, "POST", "/auth/reset", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/reset/<token>", headers, True, paths
            )

        # These are allowed to each user
        paths = self.check_endpoint(client, "GET", "/auth/status", headers, True, paths)
        paths = self.check_endpoint(
            client, "GET", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PATCH", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/auth/profile", headers, True, paths
        )
        paths = self.check_endpoint(client, "GET", "/auth/tokens", headers, True, paths)
        paths = self.check_endpoint(
            client, "DELETE", "/auth/tokens/<token>", headers, True, paths
        )

        if Connector.check_availability("pushpin"):
            paths = self.check_endpoint(
                client, "PUT", "/api/socket/<channel>/<sync>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/socket/<channel>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "PUT", "/api/stream/<channel>/<sync>", headers, True, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/stream/<channel>", headers, True, paths
            )

        # These are allowed to coordinators
        # ... none

        # These are allowed to staff
        # ... none

        # These are allowed to admins
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/users", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/groups", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/groups", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/groups/<group_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/groups/<group_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/tokens", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/tokens/<token>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/stats", headers, False, paths
        )

        # logout MUST be the last one or the token will be invalidated!! :-)
        paths = self.check_endpoint(client, "GET", "/auth/logout", headers, True, paths)

        assert paths == []

        self.delete_user(client, uuid)

    def test_public(self, client: FlaskClient) -> None:
        # List of all paths to be tested. After each test a path will be removed.
        # At the end the list is expected to be empty
        paths = self.get_paths(client)
        headers = None

        # These are public
        paths = self.check_endpoint(client, "GET", "/api/status", headers, True, paths)
        paths = self.check_endpoint(client, "GET", "/api/specs", headers, True, paths)
        paths = self.check_endpoint(client, "POST", "/auth/login", headers, True, paths)
        if Env.get_bool("ALLOW_REGISTRATION"):
            paths = self.check_endpoint(
                client, "POST", "/auth/profile", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "POST", "/auth/profile/activate", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/profile/activate/<token>", headers, True, paths
            )

        if Env.get_bool("ALLOW_PASSWORD_RESET") and Connector.check_availability(
            "smtp"
        ):
            paths = self.check_endpoint(
                client, "POST", "/auth/reset", headers, True, paths
            )
            paths = self.check_endpoint(
                client, "PUT", "/auth/reset/<token>", headers, True, paths
            )

        # These are allowed to each user
        paths = self.check_endpoint(
            client, "GET", "/auth/status", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/auth/profile", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PATCH", "/auth/profile", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/auth/profile", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/auth/tokens", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/auth/tokens/<token>", headers, False, paths
        )

        if Connector.check_availability("pushpin"):
            paths = self.check_endpoint(
                client, "PUT", "/api/socket/<channel>/<sync>", headers, False, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/socket/<channel>", headers, False, paths
            )

            paths = self.check_endpoint(
                client, "PUT", "/api/stream/<channel>/<sync>", headers, False, paths
            )

            paths = self.check_endpoint(
                client, "POST", "/api/stream/<channel>", headers, False, paths
            )

        # These are allowed to coordinators
        # ... none

        # These are allowed to staff
        # ... none

        # These are allowed to admins
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/users", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/users/<user_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/groups", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "POST", "/api/admin/groups", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "PUT", "/api/admin/groups/<group_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/groups/<group_id>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/tokens", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "DELETE", "/api/admin/tokens/<token>", headers, False, paths
        )
        paths = self.check_endpoint(
            client, "GET", "/api/admin/stats", headers, False, paths
        )

        # logout MUST be the last one or the token will be invalidated!! :-)
        paths = self.check_endpoint(
            client, "GET", "/auth/logout", headers, False, paths
        )

        assert paths == []
