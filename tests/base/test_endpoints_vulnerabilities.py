from restapi.tests import API_URI, FlaskClient


def test_vulnerabilities(client: FlaskClient) -> None:

    r = client.post(f"{API_URI}/tests/vulnerabilities/x")
    assert r.status_code == 200
