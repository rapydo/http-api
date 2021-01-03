import time
from datetime import datetime, timedelta

import pytz

from restapi.tests import AUTH_URI, BaseTests, FlaskClient


class TestApp2(BaseTests):
    def test_01_failed_login_ban(self, client: FlaskClient) -> None:

        # Let's create a new user with an expiration time of 5 seconds
        expiration_time = 5
        expiration = datetime.now(pytz.utc) + timedelta(seconds=expiration_time)
        uuid, data = self.create_user(client, data={"expiration": expiration})

        # The user is valid
        headers, _ = self.do_login(client, data["email"], data["password"])
        assert headers is not None

        # But after 5 seconds the login will be refused
        time.sleep(expiration_time)

        error = f"Sorry, this account expired on {expiration:%d %B %Y}"

        headers, _ = self.do_login(
            client, data["email"], data["password"], status_code=403, error=error
        )

        reset_data = {"reset_email": data["email"]}
        r = client.post(f"{AUTH_URI}/reset", data=reset_data)
        assert r.status_code == 403
        assert self.get_content(r) == error
