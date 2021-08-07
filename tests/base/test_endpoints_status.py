from restapi.env import Env
from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_GET_status(self, client: FlaskClient) -> None:
        """Test that the flask server is running and reachable"""

        # Check success
        alive_message = "Server is alive"

        log.info("*** VERIFY if API is online")
        r = client.get(f"{API_URI}/status")
        assert r.status_code == 200
        output = self.get_content(r)
        assert output == alive_message

        # Check failure
        log.info("*** VERIFY if invalid endpoint gives Not Found")
        r = client.get(API_URI)
        assert r.status_code == 404

        if Env.get_bool("AUTH_ENABLE"):
            # Check /auth/status with no token or invalid token
            r = client.get(f"{AUTH_URI}/status")
            assert r.status_code == 401

            r = client.get(
                f"{AUTH_URI}/status", headers={"Authorization": "Bearer ABC"}
            )
            assert r.status_code == 401
        else:
            r = client.get(f"{AUTH_URI}/status")
            assert r.status_code == 404
