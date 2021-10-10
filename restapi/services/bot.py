from marshmallow import Schema
from webargs import fields, validate

from restapi.exceptions import RestApiException
from restapi.services.telegram import BD, CD, UD, CallbackContext, Update, bot
from restapi.utilities.logs import log


@bot.command("help", help="print this help")
@bot.restricted_to_users
def usage(update: Update, context: CallbackContext[UD, CD, BD]) -> None:
    msg = "Available Commands:\n\n"

    for cmd, descr in bot.commands.items():
        msg += f" - /{cmd}\t{descr}\n"

    bot.send_markdown(msg, update)


@bot.command("me", help="info about yourself")
@bot.restricted_to_admins
def my_self(update: Update, context: CallbackContext[UD, CD, BD]) -> None:
    # Can't be true, since it is restricted_to_admins
    if not update.message or not update.message.from_user:  # pragma
        log.critical("Error: user is missing")
        return None

    user_firstname = update.message.from_user.first_name
    user_id = update.message.from_user.id
    update.message.reply_text(f"Hello {user_firstname}, your Telegram ID is {user_id}")


@bot.command("status", help="get server status", run_async=True)
@bot.restricted_to_users
def status(update: Update, context: CallbackContext[UD, CD, BD]) -> None:
    try:
        out = bot.api.get("status")
        bot.send_markdown(out, update)
    except RestApiException as e:  # pragma: no cover
        bot.send_markdown(str(e), update)


class Stats(Schema):

    param = fields.Str(
        required=True,
        validate=validate.OneOf(["disk", "cpu", "ram"]),
        metadata={"description": "Please select the type of monitor"},
    )


@bot.command("monitor", help="get server monitoring stats", run_async=True)
@bot.restricted_to_admins
@bot.parameters(Stats())
def monitor(update: Update, context: CallbackContext[UD, CD, BD], param: str) -> None:

    bot.send_markdown(f"You asked: {param}", update)
    try:
        out = bot.api.get("admin/stats")
        # Not testable for now since token sharing is not implemented
        bot.send_markdown(out, update)  # pragma: no cover
    except RestApiException as e:
        bot.send_markdown(str(e), update)
