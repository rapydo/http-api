# from datetime import datetime

import random
import time

import pytest
from click.testing import CliRunner

from restapi import __commands__ as cli
from restapi import decorators
from restapi.connectors import Connector
from restapi.server import ServerModes


def test_cli() -> None:
    runner = CliRunner()

    response = runner.invoke(cli.verify, ["test"])
    assert response.exit_code == 2

    assert "Got unexpected extra argument (test)" in response.output

    response = runner.invoke(cli.verify, ["--services", "neo4j"])
    assert response.exit_code == 2
    assert "No such option: --services" in response.output

    response = runner.invoke(cli.verify, ["--service", "x"])
    assert response.exit_code == 1

    for service in ("neo4j", "sqlalchemy"):
        if not Connector.check_availability(service):
            continue

        response = runner.invoke(cli.verify, ["--service", service])
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
    with pytest.raises(SystemExit):
        cli.get_service_address(variables, "host", "port", "myservice")

    with pytest.raises(SystemExit):
        cli.get_service_address(variables, "myhost", "port", "myservice")

    h, p = cli.get_service_address(variables, "myhost", "myport", "myservice")

    assert h == "myvalue"
    assert isinstance(p, int)
    assert p == 111

    from restapi.server import create_app

    if Connector.check_availability("redis"):
        create_app(name="Cache clearing", mode=ServerModes.NORMAL, options={})

        # make_name prevents the use of rapydo default make_name function, that is only
        # working on endpoints context since it is based on tokens from flask.request
        @decorators.cache(timeout=3600, make_name=None)
        def random_values() -> int:
            return random.randrange(0, 100000)

        val = random_values()
        time.sleep(0.9)
        assert random_values() == val
        time.sleep(0.9)
        assert random_values() == val

        # Let's clear the cache
        response = runner.invoke(cli.clearcache, [])
        assert response.exit_code == 0

        assert random_values() != val
