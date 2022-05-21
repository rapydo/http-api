from restapi.tests import API_URI, FlaskClient


def test_vulnerabilities(client: FlaskClient) -> None:

    strings = (
        "xx",
        "x'x",
        'x"x',
        "x`x",
        "x#x",
        "x--x",
        "x\\*x",
        "x*x",
        "x+x",
        "x;x",
        "x(x",
        "x)x",
    )

    for s in strings:
        r = client.get(
            f"{API_URI}/tests/vulnerabilities/{s}", query_string={"payload": s}
        )
        assert r.status_code == 200

        r = client.post(f"{API_URI}/tests/vulnerabilities/{s}", json={"payload": s})
        assert r.status_code == 200

    # Can't test x//x as url parameter
    r = client.get(
        f"{API_URI}/tests/vulnerabilities/x", query_string={"payload": "x//x"}
    )
    assert r.status_code == 200

    r = client.post(f"{API_URI}/tests/vulnerabilities/x", json={"payload": "x//x"})
    assert r.status_code == 200
