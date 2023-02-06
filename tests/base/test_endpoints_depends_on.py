from restapi.connectors import Connector
from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_depends_on(self, client: FlaskClient) -> None:
        if Connector.check_availability("neo4j"):
            r = client.get(f"{API_URI}/tests/depends_on/neo4j")
            assert r.status_code == 200

            r = client.get(f"{API_URI}/tests/depends_on_not/neo4j")
            assert r.status_code == 404

        else:
            r = client.get(f"{API_URI}/tests/depends_on/neo4j")
            assert r.status_code == 404

            r = client.get(f"{API_URI}/tests/depends_on_not/neo4j")
            assert r.status_code == 200
