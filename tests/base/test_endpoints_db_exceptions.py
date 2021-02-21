from faker import Faker

from restapi.connectors import Connector
from restapi.services.authentication import DEFAULT_GROUP_NAME
from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_database_exceptions(self, client: FlaskClient, faker: Faker) -> None:

        # This is a special value. The endpoint will try to create a group without
        # shortname. A BadRequest is expected because the database should refuse the
        # entry due to the missing property
        r = client.post(f"{API_URI}/tests/database/400")
        assert r.status_code == 400

        auth = Connector.get_authentication_instance()
        default_group = auth.get_group(name=DEFAULT_GROUP_NAME)
        assert default_group is not None

        # the /tests/database endpoint will change the default group fullname
        # as a side effect to the test the database_transaction decorator
        default_fullname = default_group.fullname

        random_name = faker.pystr()

        # This will create a new group with short/full name == random_name

        r = client.post(f"{API_URI}/tests/database/{random_name}")
        assert r.status_code == 200

        default_group = auth.get_group(name=DEFAULT_GROUP_NAME)
        assert default_group is not None

        # As a side effect the fullname of defaut_group is changed...
        assert default_group.fullname != default_fullname

        # ... and this is the new name
        new_fullname = default_group.fullname

        # This will try to create again a group with short/full name == random_name
        # but this will fail due to unique keys
        r = client.post(f"{API_URI}/tests/database/{random_name}")
        assert r.status_code == 409

        # The default group will not change again because the
        # database_transaction decorator will undo the change
        default_group = auth.get_group(name=DEFAULT_GROUP_NAME)
        assert default_group is not None

        # This cannot be verified with mongo because transactions are not implemented

        if not Connector.check_availability("mongo"):
            assert default_group.fullname == new_fullname
