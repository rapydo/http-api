"""
This will used credentials created at the beginning of the suite
to verify that unused credentialas are banned
"""

from faker import Faker

from restapi.env import Env
from restapi.tests import AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import Events

if Env.get_int("AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER") > 0:

    class TestApp1(BaseTests):
        def test_test_unused_credentials(
            self, client: FlaskClient, faker: Faker
        ) -> None:
            assert BaseTests.unused_credentials is not None
            assert len(BaseTests.unused_credentials) == 3

            data = {
                "username": BaseTests.unused_credentials[0],
                "password": faker.password(strong=True),
            }

            # Credentials are verified before the inactivity check
            r = client.post(f"{AUTH_URI}/login", json=data)
            assert r.status_code == 401
            resp = self.get_content(r)
            assert resp == "Invalid access credentials"

            data = {
                "username": BaseTests.unused_credentials[0],
                "password": BaseTests.unused_credentials[1],
            }

            # Login is blocked due to inactivity
            r = client.post(f"{AUTH_URI}/login", json=data)
            assert r.status_code == 403
            resp = self.get_content(r)
            assert resp == "Sorry, this account is blocked for inactivity"

            # Also password reset is blocked... how to recover the account !?
            reset_data = {"reset_email": BaseTests.unused_credentials[0]}
            r = client.post(f"{AUTH_URI}/reset", json=reset_data)
            assert r.status_code == 403
            resp = self.get_content(r)
            assert resp == "Sorry, this account is blocked for inactivity"

            events = self.get_last_events(2)
            assert events[0].event == Events.refused_login.value
            assert events[0].payload["username"] == BaseTests.unused_credentials[0]
            assert (
                events[0].payload["motivation"] == "account blocked due to inactivity"
            )
            assert events[1].event == Events.refused_login.value
            assert events[1].payload["username"] == BaseTests.unused_credentials[0]
            assert (
                events[1].payload["motivation"] == "account blocked due to inactivity"
            )
            assert events[1].url == "/auth/reset"

            # Goodbye temporary user
            self.delete_user(client, BaseTests.unused_credentials[2])
