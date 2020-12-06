from datetime import datetime

import pytest
from click.testing import CliRunner

from restapi import __commands__ as cli
from restapi.services.detect import detector
from restapi.tests import API_URI


def test_cli(client):
    runner = CliRunner()

    response = runner.invoke(cli.verify, [])
    assert response.exit_code == 0

    response = runner.invoke(cli.verify, ["test"])
    assert response.exit_code == 2

    assert "Got unexpected extra argument (test)" in response.output

    response = runner.invoke(cli.verify, ["--service", "neo4j"])
    assert response.exit_code == 2
    assert "Error: no such option: --service" in response.output

    response = runner.invoke(cli.verify, ["--services", "x"])
    assert response.exit_code == 1

    for service in ("neo4j", "mongo", "sqlalchemy"):
        if not detector.check_availability(service):
            continue

        response = runner.invoke(cli.verify, ["--services", service])
        assert response.exit_code == 0

    response = runner.invoke(cli.wait, [])
    assert response.exit_code == 0

    response = runner.invoke(cli.init, [])
    assert response.exit_code == 0

    response = runner.invoke(cli.init, ["--wait"])
    assert response.exit_code == 0

    response = runner.invoke(cli.clean, [])
    assert response.exit_code == 1
    assert "Do you want to continue? [y/N]:" in response.output

    response = runner.invoke(cli.tests, ["--file", "x"])
    assert response.exit_code == 1

    response = runner.invoke(cli.tests, ["--folder", "x"])
    assert response.exit_code == 1

    response = runner.invoke(cli.tests, ["--wait", "--file", "x"])
    assert response.exit_code == 1

    response = runner.invoke(cli.tests, ["--core", "--file", "x"])
    assert response.exit_code == 1

    variables = {
        "myhost": "myvalue",
        "myport": "111",
    }
    try:
        cli.get_service_address(variables, "host", "port", "myservice")
        pytest.fail("No exception raised")  # pragma: no cover
    except SystemExit:
        pass

    try:
        cli.get_service_address(variables, "myhost", "port", "myservice")
        pytest.fail("No exception raised")  # pragma: no cover
    except SystemExit:
        pass

    h, p = cli.get_service_address(variables, "myhost", "myport", "myservice")

    assert h == "myvalue"
    assert isinstance(p, int)
    assert p == 111

    # First response is not cached, expected time greater than 1 second
    start_time = datetime.now()
    r = client.patch(f"{API_URI}/tests/cache")
    end_time = datetime.now()
    assert r.status_code == 200
    assert (end_time - start_time).total_seconds() > 1

    # Second response is cached, expected time lower than 1 second
    start_time = datetime.now()
    r = client.get(f"{API_URI}/tests/cache")
    end_time = datetime.now()
    assert r.status_code == 200
    assert (end_time - start_time).total_seconds() < 1

    # Let's clear the cache
    response = runner.invoke(cli.clearcache, [])
    assert response.exit_code == 0

    # Third response is no longer cached, expected time greater than 1 second
    start_time = datetime.now()
    r = client.patch(f"{API_URI}/tests/cache")
    end_time = datetime.now()
    assert r.status_code == 200
    assert (end_time - start_time).total_seconds() > 1
