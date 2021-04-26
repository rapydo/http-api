import pytest

from restapi.env import Env
from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.globals import mem
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_users_custom_fields(self, client: FlaskClient) -> None:

        if not Env.get_bool("AUTH_ENABLED"):
            log.warning("Skipping users custom fields tests")
            return

        output_fields = mem.customizer.get_custom_output_fields(None)

        profile_inputs = mem.customizer.get_custom_input_fields(
            request=None, scope=mem.customizer.PROFILE
        )
        registration_inputs = mem.customizer.get_custom_input_fields(
            request=None, scope=mem.customizer.REGISTRATION
        )
        admin_inputs = mem.customizer.get_custom_input_fields(
            request=None, scope=mem.customizer.ADMIN
        )
        uuid, data = self.create_user(client)
        headers, _ = self.do_login(client, data["email"], data["password"])

        # Verify custom output fields (if defined) included in the profile response
        r = client.get(f"{AUTH_URI}/profile", headers=headers)
        assert r.status_code == 200
        response = self.get_content(r)

        for field in output_fields:
            assert field in response

        # Verify custom input fields (if defined) included in the profile input schema
        r = client.patch(f"{AUTH_URI}/profile", data={"get_schema": 1}, headers=headers)
        response = self.get_content(r)
        for field in profile_inputs.keys():
            for expected in response:
                if expected["key"] == field:
                    break
            else:  # pragma: no cover
                pytest.fail(f"Input field {field} not found in profile input schema")

        # Verify custom registration fields (if defined) included in the reg. schema
        r = client.post(f"{AUTH_URI}/profile", data={"get_schema": 1})
        response = self.get_content(r)
        for field in registration_inputs.keys():
            for expected in response:
                if expected["key"] == field:
                    break
            else:  # pragma: no cover
                pytest.fail(
                    f"Input field {field} not found in registration input schema"
                )

        headers, _ = self.do_login(client, None, None)
        # Verify custom admin input fields (if defined) included in admin users schema
        r = client.post(
            f"{API_URI}/admin/users", data={"get_schema": 1}, headers=headers
        )
        response = self.get_content(r)
        for field in admin_inputs.keys():
            for expected in response:
                if expected["key"] == field:
                    break
            else:  # pragma: no cover
                pytest.fail(
                    f"Input field {field} not found in admin users input schema"
                )

        # Verify custom admin output fields (if defined) included in admin users output
        r = client.get(f"{API_URI}/admin/users/{uuid}", headers=headers)
        response = self.get_content(r)
        for field in output_fields:
            # This will fail
            assert field in response
