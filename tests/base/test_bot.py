import asyncio
import re
from time import sleep

from click.testing import CliRunner
from telethon import TelegramClient
from telethon.sessions import StringSession

from restapi import __commands__ as cli
from restapi.confs import PRODUCTION
from restapi.env import Env
from restapi.utilities.logs import log
from restapi.utilities.processes import Timeout, start_timeout, stop_timeout


def test_bot():

    if not Env.get_bool("TELEGRAM_ENABLE"):
        log.warning("Skipping BOT tests: service not available")
        return False

    runner = CliRunner()

    start_timeout(3)
    try:
        runner.invoke(cli.bot, [])
    except Timeout:
        pass

    stop_timeout()

    from restapi.services.telegram import bot

    # Your API ID, hash and session string here
    api_id = Env.get_int("TELEGRAM_APP_ID")
    api_hash = Env.get("TELEGRAM_APP_HASH")
    session_str = Env.get("TELETHON_SESSION")
    botname = Env.get("TELEGRAM_BOTNAME")

    async def send_command(client, command):
        await client.send_message(botname, command)
        sleep(1)
        messages = await client.get_messages(botname)
        return messages[0].message

    async def test():
        client = TelegramClient(StringSession(session_str), api_id, api_hash)
        await client.start()

        message = await send_command(client, "/me")
        assert re.match(r"^Hello .*, your Telegram ID is [0-9]+", message)

        message = await send_command(client, "/help")
        assert "Available Commands:" in message
        assert "- /help print this help" in message
        assert "- /me info about yourself" in message
        assert "- /status get server status" in message
        assert "- /monitor get server monitoring stats" in message

        # commands requiring APIs can only be tested in PRODUCTION MODE
        if not PRODUCTION:
            log.warning("Skipping tests on BOT commands requiring APIs in DEV mode")
            return False

        message = await send_command(client, "/status")
        assert message == "Server is alive"

        message = await send_command(client, "/monitor")
        assert message == '{"param": "Missing data for required field."}'

        message = await send_command(client, "/monitor x")
        assert message == '{"x": "Must be one of: disk, cpu, ram."}'

        message = await send_command(client, "/monitor disk")
        error = "Missing credentials in headers, e.g. Authorization: 'Bearer TOKEN'"
        assert message == error

    asyncio.run(test())

    bot.shutdown()
