import time
from datetime import datetime, timedelta

import pytz

from restapi.env import Env
from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import Events, log


class TestApp2(BaseTests):
    def test_01_login_expiration(self, client: FlaskClient) -> None:
        if not Env.get_bool("MAIN_LOGIN_ENABLE") or not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping login expiration tests")
            return

        # Let's create a new user with an expiration time of N seconds
        expiration_time = 10
        expiration = datetime.now(pytz.utc) + timedelta(seconds=expiration_time)
        uuid, data = self.create_user(client, data={"expiration": expiration})

        # The user is valid
        valid_headers, _ = self.do_login(client, data["email"], data["password"])
        assert valid_headers is not None

        # But after N seconds the login will be refused
        time.sleep(expiration_time)

        invalid_headers, error = self.do_login(
            client,
            data["email"],
            data["password"],
            status_code=403,
        )
        assert invalid_headers is None
        assert error == "Sorry, this account is expired"

        events = self.get_last_events(1)
        assert events[0].event == Events.refused_login.value
        assert events[0].payload["username"] == data["email"]
        assert events[0].payload["motivation"] == "account expired"
        assert events[0].url == "/auth/login"

        # This token was valid before the expiration, but should be no longer valid
        # due to the short TTL set when emitted (capped to expiration time)
        r = client.get(f"{AUTH_URI}/status", headers=valid_headers)
        assert r.status_code == 401

        if Env.get_bool("ALLOW_PASSWORD_RESET"):
            reset_data = {"reset_email": data["email"]}
            r = client.post(f"{AUTH_URI}/reset", json=reset_data)
            assert r.status_code == 403
            assert self.get_content(r) == "Sorry, this account is expired"

            events = self.get_last_events(1)
            assert events[0].event == Events.refused_login.value
            assert events[0].payload["username"] == data["email"]
            assert events[0].payload["motivation"] == "account expired"
            assert events[0].url == "/auth/reset"

        # Let's extend the account validity for other N seconds
        admin_headers, _ = self.do_login(client, None, None)
        expiration = datetime.now(pytz.utc) + timedelta(seconds=expiration_time)
        r = client.put(
            f"{API_URI}/admin/users/{uuid}",
            json={"expiration": expiration},
            headers=admin_headers,
        )
        assert r.status_code == 204

        # The user is valid again
        valid_headers, _ = self.do_login(client, data["email"], data["password"])
        assert valid_headers is not None

        # But after N seconds the login will be refused again
        time.sleep(expiration_time)

        invalid_headers, error = self.do_login(
            client,
            data["email"],
            data["password"],
            status_code=403,
        )
        assert invalid_headers is None
        assert error == "Sorry, this account is expired"

        events = self.get_last_events(1)
        assert events[0].event == Events.refused_login.value
        assert events[0].payload["username"] == data["email"]
        assert events[0].payload["motivation"] == "account expired"
        assert events[0].url == "/auth/login"

        # Test reduction of account validity

        # Let's extent other N seconds
        admin_headers, _ = self.do_login(client, None, None)
        expiration = datetime.now(pytz.utc) + timedelta(seconds=expiration_time)
        r = client.put(
            f"{API_URI}/admin/users/{uuid}",
            json={"expiration": expiration},
            headers=admin_headers,
        )
        assert r.status_code == 204

        # The user is valid again
        valid_headers, _ = self.do_login(client, data["email"], data["password"])
        assert valid_headers is not None

        # Let's set an already expired date
        expiration = datetime.now(pytz.utc) - timedelta(seconds=expiration_time)
        r = client.put(
            f"{API_URI}/admin/users/{uuid}",
            json={"expiration": expiration},
            headers=admin_headers,
        )
        assert r.status_code == 204

        # User is no longer valid
        invalid_headers, error = self.do_login(
            client,
            data["email"],
            data["password"],
            status_code=403,
        )
        assert invalid_headers is None
        assert error == "Sorry, this account is expired"

        events = self.get_last_events(1)
        assert events[0].event == Events.refused_login.value
        assert events[0].payload["username"] == data["email"]
        assert events[0].payload["motivation"] == "account expired"
        assert events[0].url == "/auth/login"

        # This token was valid and original TTL was set >= now
        # But when the user expiration were reduced the token was invalided
        r = client.get(f"{AUTH_URI}/status", headers=valid_headers)
        assert r.status_code == 401
