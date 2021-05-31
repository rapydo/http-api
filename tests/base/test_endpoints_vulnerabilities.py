from restapi.tests import API_URI, FlaskClient


def test_vulnerabilities(client: FlaskClient) -> None:

    r = client.post(f"{API_URI}/tests/vulnerabilities/xx")
    r = client.post(f"{API_URI}/tests/vulnerabilities/x'x")
    r = client.post(f'{API_URI}/tests/vulnerabilities/x"x')
    r = client.post(f"{API_URI}/tests/vulnerabilities/x#x")
    r = client.post(f"{API_URI}/tests/vulnerabilities/x--x")
    r = client.post(f"{API_URI}/tests/vulnerabilities/x//x")
    r = client.post(f"{API_URI}/tests/vulnerabilities/x\\*x")
    r = client.post(f"{API_URI}/tests/vulnerabilities/x*x")
    r = client.post(f"{API_URI}/tests/vulnerabilities/x+x")
    r = client.post(f"{API_URI}/tests/vulnerabilities/x;x")
    r = client.post(f"{API_URI}/tests/vulnerabilities/x(x")
    r = client.post(f"{API_URI}/tests/vulnerabilities/x)x")
    assert r.status_code == 200
