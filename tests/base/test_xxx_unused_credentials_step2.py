"""
This will used credentials created at the beginning of the suite
to verify that unused credentialas are banned
"""
from restapi.env import Env
from restapi.tests import BaseTests, FlaskClient

if Env.get_int("AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER") > 0:

    class TestApp1(BaseTests):
        def test_test_unused_credentials(self, client: FlaskClient) -> None:

            assert BaseTests.unused_credentials is not None
            assert len(BaseTests.unused_credentials) == 3

            # This test will fail because the credentials should be banned!!
            headers, _ = self.do_login(
                client, BaseTests.unused_credentials[0], BaseTests.unused_credentials[1]
            )
            assert headers is not None

            # Goodbye temporary user
            self.delete_user(client, BaseTests.unused_credentials[2])
