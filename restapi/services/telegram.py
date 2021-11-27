import threading
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, cast

import orjson
import requests
from marshmallow import Schema, ValidationError, fields
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, ParseMode, Update
from telegram.error import Conflict as TelegramConflict
from telegram.ext import (
    CallbackContext,
    CallbackQueryHandler,
    CommandHandler,
    Filters,
    MessageHandler,
    Updater,
)
from telegram.ext.utils.types import BD, CD, UD

from restapi.config import CUSTOM_PACKAGE, EXTENDED_PACKAGE, EXTENDED_PROJECT_DISABLED
from restapi.env import Env
from restapi.exceptions import RestApiException, ServerError, ServiceUnavailable
from restapi.models import validate
from restapi.utilities import print_and_exit
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta
from restapi.utilities.uuid import getUUID

# it is used to pass data to inline button callbacks
data_cache = {}

CommandFunction = Callable[[Update, CallbackContext[Any, Any, Any]], None]
DecoratedCommandFunction = Callable[..., Any]


class TooManyInputs(ValidationError):
    pass


class Bot:

    #################
    #     STARTUP
    ##################

    # Startup workflow: init -> load_commands -> start
    def __init__(self) -> None:
        self.commands: Dict[str, str] = {}
        self.variables = Env.load_variables_group(prefix="telegram")
        if not self.variables.get("api_key"):  # pragma: no cover
            raise ServiceUnavailable("Missing API KEY")
        self.updater = Updater(
            self.variables.get("api_key"),
            # Starting from v13 use_context is True by default
            # use_context=True,
            workers=Env.to_int(self.variables.get("workers"), default=1),
        )

        # Inline keyboard callback
        self.updater.dispatcher.add_handler(
            CallbackQueryHandler(self.inline_keyboard_button)
        )

        # Errors
        self.updater.dispatcher.add_error_handler(self.error_callback)

        self.admins = Bot.get_ids(self.variables.get("admins"))
        if not self.admins:  # pragma: no cover
            print_and_exit("No admin list")

        self.users = Bot.get_ids(self.variables.get("users"))

        self.api = BotApiClient(self.variables)

    # Startup workflow: init -> load_commands -> start
    def load_commands(self) -> None:
        Meta.get_module_from_string("restapi.services.bot")
        if EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            Meta.get_module_from_string(f"{EXTENDED_PACKAGE}.bot")

        Meta.get_module_from_string(f"{CUSTOM_PACKAGE}.bot")

        # Handle the rest as normal messages
        # NOTE: this has to be the last handler to be attached
        self.updater.dispatcher.add_handler(
            MessageHandler(Filters.text, self.invalid_message)
        )

    def stop(self) -> None:
        self.updater.stop()
        self.updater.is_idle = False

    def shutdown(self) -> None:
        self.admins_broadcast("Bot is shutting down")
        threading.Thread(target=self.stop).start()

    # Startup workflow: init -> load_commands -> start
    def start(self) -> None:

        self.updater.start_polling(read_latency=5)
        self.admins_broadcast("Bot is ready to accept requests")
        log.info("Bot is ready to accept requests")
        self.updater.idle()
        print_and_exit("Bot closed")  # pragma: no cover

    ##################
    #    DECORATORS
    ##################

    def command(
        self, cmd: str, help: str = "N/A", run_async: bool = False
    ) -> Callable[[CommandFunction], CommandFunction]:
        def decorator(func: CommandFunction) -> CommandFunction:
            log.info("Registering {}", cmd)
            self.updater.dispatcher.add_handler(
                CommandHandler(cmd, func, pass_args=True, run_async=run_async)
            )
            self.commands[cmd] = help

            return func

        return decorator

    def restricted_to_admins(
        self, func: DecoratedCommandFunction
    ) -> DecoratedCommandFunction:
        @wraps(func)
        def wrapper(
            update: Update,
            context: CallbackContext[UD, CD, BD],
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if self.check_authorized(update, context, required_admin=True):
                return func(update, context, *args, **kwargs)

        return cast(DecoratedCommandFunction, wrapper)

    def restricted_to_users(
        self, func: DecoratedCommandFunction
    ) -> DecoratedCommandFunction:
        @wraps(func)
        def wrapper(
            update: Update,
            context: CallbackContext[UD, CD, BD],
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if self.check_authorized(update, context):
                return func(update, context, *args, **kwargs)

        return cast(DecoratedCommandFunction, wrapper)

    def parameters(
        self, schema: Schema
    ) -> Callable[[DecoratedCommandFunction], DecoratedCommandFunction]:
        def decorator(func: DecoratedCommandFunction) -> DecoratedCommandFunction:
            @wraps(func)
            def wrapper(
                update: Update,
                context: CallbackContext[UD, CD, BD],
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                # context.args == Optional[List[str]]
                # => inputs == List[str]
                inputs: List[str] = context.args or []

                # if not inputs:
                #     log.critical("Debug code: missing inputs")
                #     return None

                data = {}
                keys = list(schema.declared_fields.keys())
                # Verify if the number of inputs exceed the number of defined parameters
                if len(inputs) > len(keys):
                    raise TooManyInputs("")

                # Map allgiven inputs to the correspoding parameter, based on definition
                # order. 1st input = 1st parameter, 2nd input = 2nd parameter up to Nth
                for idx, k in enumerate(keys):
                    if idx < len(inputs):
                        data[k] = inputs[idx]

                # Now inputs list is converted in a dictionary of parameters that can be
                # validated against the Marshamallow schema
                try:
                    val = schema.load(data)
                except ValidationError as e:
                    # One or more parameters raised a validation error.
                    # Get the first error based on parameter definition order. e.g.
                    # param 1 = ok
                    # param 2 = error2
                    # param 3 = error3
                    # => raise error2
                    # Please note that e.messages is not ordered and error3 could be
                    # listed before error2, a match against schema.declared_fields is
                    # Needed to guarantee the right order
                    for param, definition in schema.declared_fields.items():
                        if param not in e.messages:  # pragma: no cover
                            continue
                        # This is the first parameter raising validation errors. In case
                        # of enums a InlineKeyboardButton will be shown and the result
                        # will be passed to the wrapper to re-validate the schema with
                        # an additional parameter
                        self.manage_missing_parameter(
                            wrapper,
                            param,
                            definition,
                            update,
                            context,
                            e.messages[param],  # type: ignore
                        )
                        break

                    return None

                return func(update, context, *args, **val, **kwargs)

            return cast(DecoratedCommandFunction, wrapper)

        return decorator

    #################
    #    MESSAGES
    ##################

    def send_markdown(self, msg: str, update: Update) -> None:
        if not msg.strip():  # pragma: no cover
            return

        if update.message:
            self.updater.bot.send_message(
                chat_id=update.message.chat_id,
                text=msg.replace("_", "-"),
                parse_mode=ParseMode.MARKDOWN,
            )
        else:  # pragma: no cover
            log.critical("Debug code: update.message in missing in send_markdown")

    def admins_broadcast(self, msg: str) -> None:
        for admin in self.admins:
            self.updater.bot.send_message(chat_id=admin, text=msg)

    ###########################################
    #   CALLBACKS AND OTHER SERVICE FUNCTIONS
    #          mostly private methods
    ##########################################

    # Strange, but update is expected to be object, not : Update
    def error_callback(self, update: Any, context: CallbackContext[UD, CD, BD]) -> None:
        # https://github.com/python-telegram-bot/python-telegram-bot/wiki/Exception-Handling
        if isinstance(context.error, TooManyInputs):
            update.message.reply_text("Too many inputs", parse_mode=ParseMode.MARKDOWN)
        # Two instances running on the same account
        elif isinstance(context.error, TelegramConflict):  # pragma: no cover
            self.admins_broadcast(str(context.error))
            log.warning("Stopping bot...")
            self.shutdown()
        # Never happens during tests... how to test it?
        else:  # pragma: no cover
            log.error(context.error)
            self.admins_broadcast(str(context.error))

    def invalid_message(
        self, update: Update, context: CallbackContext[UD, CD, BD]
    ) -> None:

        if update.message:
            user = update.message.from_user.id if update.message.from_user else "N/A"
            log.info(
                "Received invalid message from {}: {}",
                user,
                update.message.text,
            )
            if self.check_authorized(update, context):
                self.updater.bot.send_message(
                    chat_id=update.message.chat_id,
                    text="Invalid command, ask for /help",
                )
        else:  # pragma: no cover
            log.critical("Debug code: update.message in missing in invalid_message")

    def manage_missing_parameter(
        self,
        func: Any,
        param: str,
        definition: fields.Field,
        update: Update,
        context: CallbackContext[UD, CD, BD],
        error: List[str],
    ) -> None:

        if not update.message:  # pragma
            log.critical("Debug code: missing message in manage_missing_parameter")
            return None

        # Parameters without description should raise some kind of errors/warnings?
        if "description" in definition.metadata:
            description = definition.metadata["description"]
        else:  # pragma: no cover
            description = "???"

        # Enum -> InlineKeyboardButton
        if definition.validate and isinstance(definition.validate, validate.OneOf):

            choices = definition.validate.choices
            labels = definition.validate.labels
            if len(tuple(labels)) != len(tuple(choices)):
                labels = choices

            keyboard = []
            for k, val in dict(zip(choices, labels)).items():
                data_key = getUUID()
                # Because func, update and context are not (easily) serializable they
                # are saved in a data_cache and the callback will access them
                # by using the assigned unique data_key
                data_cache[data_key] = {
                    "func": func,
                    "update": update,
                    "context": context,
                    "parameter": k,
                }

                # All InlineKeyboardButton are registered with one single callback
                # function (SIGH and SOB!!). The data_key passed as callback_data will
                # be used to access the specific data and call again the command func
                # by augmenting the parameters list with the choice from the button
                keyboard.append([InlineKeyboardButton(val, callback_data=data_key)])
            reply_markup = InlineKeyboardMarkup(keyboard)

            update.message.reply_text(description, reply_markup=reply_markup)
        # Other errors
        # Never raised during tests
        else:  # pragma: no cover
            update.message.reply_text(f"{description}\n{param}: {error[0]}")

    # Callback used by ALL inline keyboard button. It will received a data_key
    # as callback_data to access to data from the specific commands
    # Not called during tests... how to test it?
    def inline_keyboard_button(
        self, update: Update, context: CallbackContext[UD, CD, BD]
    ) -> None:  # pragma: no cover
        query = update.callback_query

        if not query:
            log.critical("Debug code: query is empty in inline_keyboard_button")
            return None

        # Callback queries need to be answered, even if no notification to the user
        # is needed. Some clients may have trouble otherwise.
        # See https://core.telegram.org/bots/api#callbackquery
        query.answer()

        # The data cache contains the parameters wrapper of the command function. This
        # wrapper will be invoked by augmenting the original list of parameters with
        # the choice obtained from the inline keyboard argument

        if not query.data:
            log.critical("Debug code: query.data is empty in inline_keyboard_button")
            return None

        data = data_cache.pop(query.data)
        query.edit_message_text(text=f"Selected option: {data['parameter']}")
        # func is the parameters wrapper of the command function
        func = data["func"]
        # original context args are augmented with the new choice
        data["context"].args.append(data["parameter"])

        # Let's invoke the parameters wrapper with the new additional parameter
        func(data["update"], data["context"])

    def is_authorized(self, user_id: int, required_admin: bool) -> bool:

        if required_admin:
            return user_id in self.admins

        return user_id in self.admins + self.users

    def check_authorized(
        self,
        update: Update,
        context: CallbackContext[UD, CD, BD],
        required_admin: bool = False,
    ) -> bool:

        if not update.message or not update.message.from_user:
            log.critical("Debug code: missing user in check_authorized")
            return False

        user = update.message.from_user
        user_id = user.id
        text = update.message.text

        if self.is_authorized(user_id, required_admin):
            log.info(f"User {user_id} requested: {text}")
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
        self.admins_broadcast(msg)

        self.updater.bot.send_message(
            chat_id=update.message.chat_id,
            text="Permission denied, you are not authorized to execute this command",
        )
        return False

    @staticmethod
    def get_ids(ids_list: Optional[str]) -> List[int]:
        if not ids_list:
            return []

        try:
            return [int(x.strip()) for x in ids_list.split(",")]
        except ValueError as e:  # pragma: no cover
            log.error(e)
            return []


class BotApiClient:

    variables: Dict[str, str] = {}

    def __init__(self, variables: Dict[str, str]) -> None:
        BotApiClient.variables = variables

    @staticmethod
    def get(path: str, base: str = "api") -> Any:
        return BotApiClient.api(path, "GET", base=base)

    # Not executed during tests... no command implemented on that api method
    @staticmethod
    def put(path: str, base: str = "api") -> Any:  # pragma: no cover
        return BotApiClient.api(path, "PUT", base=base)

    # Not executed during tests... no command implemented on that api method
    @staticmethod
    def patch(path: str, base: str = "api") -> Any:  # pragma: no cover
        return BotApiClient.api(path, "PATCH", base=base)

    # Not executed during tests... no command implemented on that api method
    @staticmethod
    def post(
        path: str, base: str = "api", payload: Optional[Dict[str, Any]] = None
    ) -> Any:  # pragma: no cover
        return BotApiClient.api(path, "POST", base=base, payload=payload)

    # Not executed during tests... no command implemented on that api method
    @staticmethod
    def delete(path: str, base: str = "api") -> Any:  # pragma: no cover
        return BotApiClient.api(path, "DELETE", base=base)

    @staticmethod
    def api(
        path: str,
        method: str,
        base: str = "api",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Any:
        host = BotApiClient.variables.get("backend_host")
        port = Env.get("FLASK_PORT", "8080")
        url = f"http://{host}:{port}/{base}/{path}"

        log.debug("Calling {} on {}", method, url)

        try:
            data: Optional[str] = None
            if payload:
                data = orjson.dumps(payload).decode("UTF8")

            response = requests.request(method, url=url, data=data, timeout=10)

            out = response.json()
        # Never raised during tests: how to test it?
        except Exception as e:  # pragma: no cover
            log.error(f"API call failed: {e}")
            raise ServerError(str(e))

        if response.status_code >= 300:
            raise RestApiException(out, status_code=response.status_code)

        return out


bot = Bot()
