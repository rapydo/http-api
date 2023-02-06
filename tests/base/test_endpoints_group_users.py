from faker import Faker

from restapi.env import Env
from restapi.services.authentication import Role
from restapi.tests import API_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_group_users(self, client: FlaskClient, faker: Faker) -> None:
        if not Env.get_bool("MAIN_LOGIN_ENABLE") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping group/users tests")
            return

        # Create group 1 with 1 Coordinator and 1 User
        group1_uuid, _ = self.create_group(client)
        _, user1_data = self.create_user(
            client, roles=[Role.COORDINATOR], data={"group": group1_uuid}
        )
        _, user2_data = self.create_user(
            client, roles=[Role.USER], data={"group": group1_uuid}
        )

        # Create group 2 with only 1 Coordinator
        group2_uuid, _ = self.create_group(client)

        _, user3_data = self.create_user(
            client, roles=[Role.COORDINATOR], data={"group": group2_uuid}
        )

        # Verify POST / PUT and DELETE are not enabled
        headers, _ = self.do_login(client, user1_data["email"], user1_data["password"])

        r = client.post(f"{API_URI}/group/users", headers=headers)
        assert r.status_code == 405

        r = client.put(f"{API_URI}/group/users", headers=headers)
        assert r.status_code == 405

        r = client.delete(f"{API_URI}/group/users", headers=headers)
        assert r.status_code == 405

        r = client.put(f"{API_URI}/group/users/{group1_uuid}", headers=headers)
        assert r.status_code == 404

        r = client.delete(f"{API_URI}/group/users/{group1_uuid}", headers=headers)
        assert r.status_code == 404

        # Verify GET response

        r = client.get(f"{API_URI}/group/users", headers=headers)
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, list)

        assert response is not None
        assert len(response) == 2
        assert "email" in response[0]
        assert "name" in response[0]
        assert "surname" in response[0]
        assert "roles" in response[0]
        assert "password" not in response[0]
        assert "uuid" not in response[0]
        assert "group" not in response[0]
        assert "belongs_to" not in response[0]
        assert "first_login" not in response[0]
        assert "last_login" not in response[0]
        assert "last_password_change" not in response[0]
        assert "is_active" not in response[0]
        assert "privacy_accepted" not in response[0]
        assert "expiration" not in response[0]

        email1 = response[0]["email"]
        email2 = response[1]["email"]

        assert email1 == user1_data["email"] or email2 == user1_data["email"]
        assert email1 == user2_data["email"] or email2 == user2_data["email"]
        assert email1 != user3_data["email"] and email2 != user3_data["email"]

        # Verify GET response with the other group

        headers, _ = self.do_login(client, user3_data["email"], user3_data["password"])

        r = client.get(f"{API_URI}/group/users", headers=headers)
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, list)

        assert response is not None
        assert len(response) == 1
        assert "email" in response[0]
        assert "name" in response[0]
        assert "surname" in response[0]
        assert "roles" in response[0]
        assert "password" not in response[0]
        assert "uuid" not in response[0]
        assert "group" not in response[0]
        assert "belongs_to" not in response[0]
        assert "first_login" not in response[0]
        assert "last_login" not in response[0]
        assert "last_password_change" not in response[0]
        assert "is_active" not in response[0]
        assert "privacy_accepted" not in response[0]
        assert "expiration" not in response[0]

        assert response[0]["email"] == user3_data["email"]
        assert response[0]["email"] != user1_data["email"]
        assert response[0]["email"] != user2_data["email"]

        # Add an admin to group1
        _, user4_data = self.create_user(
            client, roles=[Role.ADMIN, Role.COORDINATOR], data={"group": group1_uuid}
        )

        # Verify as Admin AND Coordinator (Expected: all members, including admins)
        headers, _ = self.do_login(client, user4_data["email"], user4_data["password"])

        r = client.get(f"{API_URI}/group/users", headers=headers)
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, list)
        members = {r["email"] for r in response}
        assert len(members) == 3

        assert user1_data["email"] in members
        assert user2_data["email"] in members
        assert user3_data["email"] not in members
        assert user4_data["email"] in members

        # Verify as Coordinator only (Expected: admins to be filtered out)
        headers, _ = self.do_login(client, user1_data["email"], user1_data["password"])

        r = client.get(f"{API_URI}/group/users", headers=headers)
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, list)
        members = {r["email"] for r in response}

        assert len(members) == 2

        assert user1_data["email"] in members
        assert user2_data["email"] in members
        assert user3_data["email"] not in members
        assert user4_data["email"] not in members
