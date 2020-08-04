import pytest
from click.testing import CliRunner

from restapi import __commands__ as cli
from restapi.env import Env
from restapi.services.detect import detector
from restapi.utilities.processes import Timeout, start_timeout, stop_timeout


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

    if Env.get_bool("TELEGRAM_ENABLE"):
        start_timeout(6)
        try:
            runner.invoke(cli.bot, [])
        except Timeout:
            pass

        stop_timeout()

        from telethon import TelegramClient
        from telethon.sessions import StringSession

        from restapi.services.telegram import bot

        # Your API ID, hash and session string here
        api_id = Env.get_int("TELEGRAM_APP_ID")
        api_hash = Env.get("TELEGRAM_APP_HASH")
        session_str = Env.get("TELETHON_SESSION")
        botname = Env.get("TELEGRAM_BOTNAME")

        client = TelegramClient(
            StringSession(session_str), api_id, api_hash, sequential_updates=True
        )
        client.start()
        client.send_message(botname, "/status")
        messages = await client.get_messages(botname)
        assert messages[0].message == "Server is alive"

        bot.shutdown()

    variables = {
        "myhost": "myvalue",
        "myport": "111",
    }
    try:
        cli.get_service_address(variables, "host", "port", "myservice")
        pytest.fail("No exception raised")
    except SystemExit:
        pass

    try:
        cli.get_service_address(variables, "myhost", "port", "myservice")
        pytest.fail("No exception raised")
    except SystemExit:
        pass

    h, p = cli.get_service_address(variables, "myhost", "myport", "myservice")

    assert h == "myvalue"
    assert isinstance(p, int)
    assert p == 111
