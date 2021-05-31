from restapi.tests import API_URI, FlaskClient


def test_vulnerabilities(client: FlaskClient) -> None:

    r = client.get(f"{API_URI}/tests/vulnerabilities/xx")
    r = client.get(f"{API_URI}/tests/vulnerabilities/x'x")
    r = client.get(f'{API_URI}/tests/vulnerabilities/x"x')
    r = client.get(f"{API_URI}/tests/vulnerabilities/x#x")
    r = client.get(f"{API_URI}/tests/vulnerabilities/x--x")
    r = client.get(f"{API_URI}/tests/vulnerabilities/x//x")
    r = client.get(f"{API_URI}/tests/vulnerabilities/x\\*x")
    r = client.get(f"{API_URI}/tests/vulnerabilities/x*x")
    r = client.get(f"{API_URI}/tests/vulnerabilities/x+x")
    r = client.get(f"{API_URI}/tests/vulnerabilities/x;x")
    r = client.get(f"{API_URI}/tests/vulnerabilities/x(x")
    r = client.get(f"{API_URI}/tests/vulnerabilities/x)x")
    assert r.status_code == 200
