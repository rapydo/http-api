from restapi.tests import API_URI, AUTH_URI, BaseTests
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_GET_status(self, client):
        """ Test that the flask server is running and reachable """

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

        # Check HTML response to status if agent/request is text/html
        # this is a ApiSpec endpoint
        headers = {"Accept": "text/html"}
        r = client.get(f"{API_URI}/status", headers=headers)
        assert r.status_code == 200
        output = r.data.decode("utf-8")
        assert output != alive_message
        assert alive_message in output
        assert "<html" in output
        assert "<body>" in output

        # Check /auth/status with no token or invalid token
        r = client.get(f"{AUTH_URI}/status")
        assert r.status_code == 401

        r = client.get(f"{AUTH_URI}/status", headers={"Authorization": "Bearer ABC"})
        assert r.status_code == 401