import json
from functools import wraps

import requests
from marshmallow import ValidationError
from telegram import ParseMode
from telegram.ext import CommandHandler, Filters, MessageHandler, Updater

from restapi.confs import get_backend_url
from restapi.env import Env
from restapi.exceptions import RestApiException
from restapi.services.detect import Detector
from restapi.utilities.logs import log


class TooManyInputs(ValidationError):
    pass


class Bot:
    def __init__(self):
        self.commands = {}
        self.variables = Detector.load_variables(prefix="telegram")
        self.updater = Updater(
            self.variables.get("api_key"),
            use_context=True,
            workers=Env.to_int(self.variables.get("workers"), default=1),
        )

        # Errors
        self.updater.dispatcher.add_error_handler(self.error_callback)

        self.admins = Bot.get_ids(self.variables.get("admins"))
        if not self.admins:
            log.exit("No admin list")

        self.users = Bot.get_ids(self.variables.get("users"))

    @staticmethod
    def get_ids(ids_list):
        if not ids_list:
            return []

        try:
            return [int(x.strip()) for x in ids_list.split(",")]
        except ValueError as e:
            log.error(e)
            return []

    def error_callback(self, update, context):
        if isinstance(context.error, TooManyInputs):
            update.message.reply_text("Too many inputs", parse_mode=ParseMode.MARKDOWN)
        elif isinstance(context.error, ValidationError):
            errors = {}
            for k in context.error.messages:
                if k in context.error.data:
                    errors[context.error.data[k]] = context.error.messages[k]
                else:
                    errors[k] = context.error.messages[k]

            update.message.reply_text(errors, parse_mode=ParseMode.MARKDOWN)

        else:
            # https://github.com/python-telegram-bot/python-telegram-bot/wiki/Exception-Handling
            log.error(context.error)
            update.message.reply_text("Unexpected error", parse_mode=ParseMode.MARKDOWN)
        # raise context.error

    def start(self):

        # Handle the rest as normal messages
        # NOTE: this has to be the last handler to be attached
        self.updater.dispatcher.add_handler(
            MessageHandler(Filters.text, self.invalid_message)
        )

        self.updater.start_polling(read_latency=5)
        log.info("Bot is ready to accept requests")
        return self.updater.idle()

    def command(self, cmd, help="N/A"):
        def decorator(func):
            log.info("Registering {}", cmd)
            self.updater.dispatcher.add_handler(
                CommandHandler(cmd, func, pass_args=True)
            )
            self.commands[cmd] = help

            return func

        return decorator

    def restricted_to_users(self, func):
        @wraps(func)
        def wrapper(update, context, *args, **kwargs):
            if self.check_authorized(update, context):
                return func(update, context, *args, **kwargs)

        return wrapper

    def parameters(self, schema):
        def decorator(func):
            @wraps(func)
            def wrapper(update, context, *args, **kwargs):
                inputs = context.args
                data = {}
                keys = list(schema.declared_fields.keys())
                if len(inputs) > len(keys):
                    raise TooManyInputs("")

                for idx, k in enumerate(keys):
                    if idx < len(inputs):
                        data[k] = inputs[idx]

                val = schema.load(data)
                return func(update, context, *args, **val, **kwargs)

            return wrapper

        return decorator

    def restricted_to_admins(self, func):
        @wraps(func)
        def wrapper(update, context, *args, **kwargs):
            if self.check_authorized(update, context, required_admin=True):
                return func(update, context, *args, **kwargs)

        return wrapper

    def is_authorized(self, user_id, required_admin):

        if required_admin:
            return user_id in self.admins

        return user_id in self.admins + self.users

    def admins_broadcast(self, context, msg):
        for admin in self.admins:
            context.bot.send_message(chat_id=admin, text=msg)

    def check_authorized(self, update, context, required_admin=False):
        user = update.message.from_user
        user_id = user.id
        text = update.message.text

        if self.is_authorized(user_id, required_admin):
            log.info(f"User {user_id} calls restricted: '{text}'")
            return True

        msg = "Unauthorized request!\n"
        for key, value in update.message.__dict__.items():
            if key == "from_user":
                for k, v in value.__dict__.items():
                    if not k.startswith("_") and v is not None:
                        msg += f"{k}: {v}\n"
            if key in ["date", "photo", "text"]:
                # print(key, value)
                if key == "text":
                    msg += f"{key}: {value}\n"
        log.warning(msg)
        # Notify admins about violation
        self.admins_broadcast(context, msg)

        context.bot.send_message(
            chat_id=update.message.chat_id, text="Invalid command, ask for /help"
        )
        return False

    def invalid_message(self, update, context):
        log.info(
            "Received invalid message from {}: {}",
            update.message.from_user.id,
            update.message.text,
        )
        if self.check_authorized(update, context):
            context.bot.send_message(
                chat_id=update.message.chat_id, text="Invalid command, ask for /help"
            )

    @staticmethod
    def send_markdown(msg, context, update):
        if not msg.strip():
            return

        context.bot.send_message(
            chat_id=update.message.chat_id,
            text=msg.replace("_", "-"),
            parse_mode=ParseMode.MARKDOWN,
        )

    @staticmethod
    def api(path, payload=None, method="post", base="api"):
        url = get_backend_url()
        url = f"{url}/{base}/{path}"
        log.debug("Calling {} on {}", method, url)
        if payload and method in ["post"]:
            payload = json.dumps(payload)

        try:
            response = requests.request(method, url=url, data=payload)

            out = response.json()
        except Exception as e:
            log.error(f"API call failed: {e}")
            raise RestApiException(str(e), status_code=500)

        if response.status_code >= 300:
            raise RestApiException(out, status_code=response.status_code)

        return out


bot = Bot()
