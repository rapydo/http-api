# -*- coding: utf-8 -*-
from click.testing import CliRunner
from restapi import __commands__ as cli
from restapi.services.detect import detector


def test_cli():
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

    for service in ('neo4j', 'mongo', 'sqlalchemy'):
        if not detector.check_availability(service):
            continue

        response = runner.invoke(cli.verify, ["--services", service])
        assert response.exit_code == 0

    response = runner.invoke(cli.wait, [])
    assert response.exit_code == 0

    response = runner.invoke(cli.init, [])
    assert response.exit_code == 0

    response = runner.invoke(cli.clean, [])
    assert response.exit_code == 1
    'Do you want to continue? [y/N]:' in response.output

    response = runner.invoke(cli.tests, ["--file", "x"])
    assert response.exit_code == 1

    response = runner.invoke(cli.tests, ["--folder", "x"])
    assert response.exit_code == 1
