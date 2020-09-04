from marshmallow import Schema
from telegram.ext.dispatcher import run_async
from webargs import fields, validate

from restapi.exceptions import RestApiException
from restapi.services.telegram import bot


@bot.command("help", help="print this help")
@bot.restricted_to_users
def usage(update, context):
    msg = "Available Commands:\n\n"

    for cmd, descr in bot.commands.items():
        msg += f" - /{cmd}\t{descr}\n"

    bot.send_markdown(msg, update)


@bot.command("me", help="info about yourself")
@bot.restricted_to_admins
def my_self(update, context):
    user_firstname = update.message.from_user.first_name
    user_id = update.message.from_user.id
    return update.message.reply_text(
        f"Hello {user_firstname}, your Telegram ID is {user_id}"
    )


@bot.command("status", help="get server status")
@bot.restricted_to_users
@run_async
def status(update, context):
    try:
        out = bot.api.get("status")
        bot.send_markdown(out, update)
    except RestApiException as e:
        bot.send_markdown(str(e), update)


class Stats(Schema):

    param = fields.Str(
        required=True,
        validate=validate.OneOf(["disk", "cpu", "ram"]),
        description="Please select the type of monitor",
    )


@bot.command("monitor", help="get server monitoring stats")
@bot.restricted_to_admins
@bot.parameters(Stats())
@run_async
def monitor(update, context, param):

    bot.send_markdown(f"You asked: {param}", update)
    try:
        out = bot.api.get("admin/stats")
        bot.send_markdown(out, update)
    except RestApiException as e:
        bot.send_markdown(str(e), update)
