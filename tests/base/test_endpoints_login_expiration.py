import time
from datetime import datetime, timedelta

import pytz

from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient


class TestApp2(BaseTests):
    def test_01_failed_login_ban(self, client: FlaskClient) -> None:

        # Let's create a new user with an expiration time of 5 seconds
        expiration_time = 5
        expiration = datetime.now(pytz.utc) + timedelta(seconds=expiration_time)
        uuid, data = self.create_user(client, data={"expiration": expiration})

        # The user is valid
        valid_headers, _ = self.do_login(client, data["email"], data["password"])
        assert valid_headers is not None

        # But after 5 seconds the login will be refused
        time.sleep(expiration_time)

        error = f"Sorry, this account expired on {expiration:%d %B %Y}"

        invalid_headers, _ = self.do_login(
            client, data["email"], data["password"], status_code=403, error=error
        )
        assert invalid_headers is None

        reset_data = {"reset_email": data["email"]}
        r = client.post(f"{AUTH_URI}/reset", data=reset_data)
        assert r.status_code == 403
        assert self.get_content(r) == error

        # Let's extend the account validity for other 5 seconds
        admin_headers, _ = self.do_login(client, None, None)
        expiration = datetime.now(pytz.utc) + timedelta(seconds=expiration_time)
        r = client.put(
            f"{API_URI}/admin/users/{uuid}",
            data={"expiration": expiration},
            headers=admin_headers,
        )

        # The user is valid again
        valid_headers, _ = self.do_login(client, data["email"], data["password"])
        assert valid_headers is not None

        # But after 5 seconds the login will be refused again
        time.sleep(expiration_time)

        invalid_headers, _ = self.do_login(
            client, data["email"], data["password"], status_code=403, error=error
        )
        assert invalid_headers is None
