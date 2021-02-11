"""
This will used credentials created at the beginning of the suite
to verify that unused credentialas are banned
"""
from faker import Faker

from restapi.env import Env
from restapi.tests import AUTH_URI, BaseTests, FlaskClient

if Env.get_int("AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER") > 0:

    class TestApp1(BaseTests):
        def test_test_unused_credentials(
            self, client: FlaskClient, fake: Faker
        ) -> None:

            assert BaseTests.unused_credentials is not None
            assert len(BaseTests.unused_credentials) == 3

            data = {
                "username": BaseTests.unused_credentials[0],
                "password": fake.password(strong=True),
            }

            # Credentials are verified before the inactivity check
            r = client.post(f"{AUTH_URI}/login", data=data)
            assert r.status_code == 401
            resp = self.get_content(r)
            assert resp == "Invalid access credentials"

            data = {
                "username": BaseTests.unused_credentials[0],
                "password": BaseTests.unused_credentials[1],
            }

            # Login is blocked due to inactivity
            r = client.post(f"{AUTH_URI}/login", data=data)
            assert r.status_code == 403
            resp = self.get_content(r)
            assert resp == "Sorry, this account is blocked for inactivity"

            # Also password reset and blocked... how to recover the account !?

            reset_data = {"reset_email": BaseTests.unused_credentials[0]}
            r = client.post(f"{AUTH_URI}/reset", data=reset_data)
            assert r.status_code == 403
            resp = self.get_content(r)
            assert resp == "Sorry, this account is blocked for inactivity"

            # Goodbye temporary user
            self.delete_user(client, BaseTests.unused_credentials[2])
