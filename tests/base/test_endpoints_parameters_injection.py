from restapi.env import Env
from restapi.services.authentication import BaseAuthentication
from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_parameter_injection(self, client: FlaskClient) -> None:
        if Env.get_bool("AUTH_ENABLE"):
            headers, _ = self.do_login(client, None, None)
            r = client.get(f"{API_URI}/tests/inject/myparam", headers=headers)
            assert r.status_code == 200

            response = self.get_content(r)
            assert isinstance(response, list)
            assert len(response) == 3

            # User is injected by the authentication decorator
            assert response[0] == BaseAuthentication.default_user
            # myparam is injected as url parameter
            assert response[1] == "myparam"
            # default_value is injected only because it has a... default value
            assert response[2] == "default_value"
