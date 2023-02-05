"""
Here some credentials will be created to be used at the end of the suite
to verify that unused credentials are banned
"""

from faker import Faker

from restapi.env import Env
from restapi.tests import BaseTests, FlaskClient

if Env.get_int("AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER") > 0:

    class TestApp1(BaseTests):
        def test_create_credentials(self, client: FlaskClient, faker: Faker) -> None:
            # Assign to a new group to prevent that tests working on the
            # default group could delete this user
            group_data = {
                "fullname": "Group to unused credentials",
                "shortname": faker.pystr(min_chars=12, max_chars=12),
            }

            group_uuid, _ = self.create_group(client, group_data)
            user_uuid, user_data = self.create_user(client, group=group_uuid)

            BaseTests.unused_credentials = (
                user_data["email"],
                user_data["password"],
                user_uuid,
            )
            headers, _ = self.do_login(
                client, BaseTests.unused_credentials[0], BaseTests.unused_credentials[1]
            )
            assert headers is not None
