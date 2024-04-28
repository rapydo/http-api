import pytest
from faker import Faker

from restapi.env import Env
from restapi.services.authentication import BaseAuthentication
from restapi.tests import API_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_admin_stats(self, client: FlaskClient, faker: Faker) -> None:
        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping admin/logins tests")
            return

        r = client.get(f"{API_URI}/admin/logins")
        assert r.status_code == 401

        random_username = faker.ascii_email()
        self.do_login(client, random_username, faker.pystr(), status_code=401)

        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/admin/logins", headers=headers)
        assert r.status_code == 200
        logins = self.get_content(r)
        assert isinstance(logins, list)
        assert len(logins) > 0
        assert "username" in logins[0]
        assert "date" in logins[0]
        assert "IP" in logins[0]
        assert "location" in logins[0]
        assert "failed" in logins[0]
        assert "flushed" in logins[0]

        for login in logins:
            if login["username"] == BaseAuthentication.default_user:
                break
        else:  # pragma: no cover
            pytest.fail("Default user not found in logins table")

        for login in logins:
            if login["username"] == random_username:
                assert login["failed"] is True
                assert login["flushed"] is False
                break
        else:  # pragma: no cover
            pytest.fail("Random user not found in logins table")
