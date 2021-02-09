"""
Here some credentials will be created to be used at the end of the suite
to verify that unused credentials are banned
"""

from restapi.env import Env
from restapi.tests import BaseTests, FlaskClient

if Env.get_int("AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER") > 0:

    class TestApp1(BaseTests):
        def test_create_credentials(self, client: FlaskClient) -> None:
            uuid, data = self.create_user(client)

            BaseTests.unused_credentials = (data["email"], data["password"], uuid)
            headers, _ = self.do_login(
                client, BaseTests.unused_credentials[0], BaseTests.unused_credentials[1]
            )
            assert headers is not None
