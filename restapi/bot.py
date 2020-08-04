from marshmallow import Schema
from telegram.ext.dispatcher import run_async
from webargs import fields, validate

from restapi.exceptions import RestApiException
from restapi.services.telegram import bot

# from restapi.utilities.logs import log


@bot.command("help", help="print this help")
@bot.restricted_to_users
def help(update, context):
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


# class Test(Schema):
#     a = fields.Int()
#     b = fields.Str(required=True)
#     c = fields.Bool(missing=False)


# def handle_test_output(data):
#     if len(data) < 1:
#         return "No test"
#     msg = "test:\n\n"
#     for element in data:
#         msg += f"- `{element}`\n"
#     return msg

# @bot.command("test")
# @bot.restricted_to_users
# @bot.parameters(Test())
# @run_async
# def test(update, context, a, b, c):
#     if out := bot.api(path="test"):
#         msg = handle_error(out, do_if_ok=handle_test_output)
#     else:
#         msg = "Invalid request"
#     bot.send_markdown(msg, update)


@bot.command("status", help="get server status")
@bot.restricted_to_users
@run_async
def status(update, context):
    try:
        out = bot.api("status", method="get")
        bot.send_markdown(out, update)
    except RestApiException as e:
        bot.send_markdown(str(e), update)


class Stats(Schema):
    param = fields.Str(required=True, validate=validate.OneOf(["disk", "cpu", "ram"]))


@bot.command("monitor", help="get server monitoring stats")
@bot.restricted_to_admins
@bot.parameters(Stats())
@run_async
def monitor(update, context, param):
    try:
        out = bot.api("admin/stats", method="get")
        bot.send_markdown(out, update)
    except RestApiException as e:
        bot.send_markdown(str(e), update)
