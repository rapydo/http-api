"""
Celery connector with automatic integration in rapydo framework
"""

import ssl
import traceback
from datetime import timedelta
from functools import wraps
from typing import (
    Any,
    Callable,
    Dict,
    List,
    NoReturn,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

import certifi
from celery import Celery, states
from celery.exceptions import Ignore

from restapi.config import CUSTOM_PACKAGE, DOCS, HOST_TYPE, SSL_CERTIFICATE, TESTING
from restapi.connectors import Connector, ExceptionsList
from restapi.connectors.rabbitmq import RabbitExt
from restapi.connectors.redis import RedisExt
from restapi.connectors.smtp.notifications import send_celery_error_notification
from restapi.env import Env
from restapi.utilities import print_and_exit
from restapi.utilities.logs import log, obfuscate_url
from restapi.utilities.meta import Meta
from restapi.utilities.time import AllowedTimedeltaPeriods, get_timedelta

REDBEAT_KEY_PREFIX: str = "redbeat:"

F = TypeVar("F", bound=Callable[..., Any])


class CeleryRetryTask(Exception):
    pass


def mark_task_as_failed(self: Any, name: str, exception: Exception) -> NoReturn:
    if TESTING:
        self.request.id = "fixed-id"
        self.request.task = name

    task_id = self.request.id
    task_name = self.request.task
    arguments = str(self.request.args)

    # Removing username and password from urls in error stack
    clean_error_stack = ""
    for line in traceback.format_exc().split("\n"):
        clean_error_stack += f"{obfuscate_url(line)}\n"

    log.error("Celery task {} ({}) failed", task_id, task_name)
    log.error("Failed task arguments: {}", arguments[0:256])
    log.error("Task error: {}", clean_error_stack)

    if Connector.check_availability("smtp"):
        log.info("Sending error report by email", task_id, task_name)
        send_celery_error_notification(
            task_id, task_name, arguments, clean_error_stack, -1
        )
    self.update_state(
        state=states.FAILURE,
        meta={
            "exc_type": type(exception).__name__,
            "exc_message": traceback.format_exc().split("\n"),
            # 'custom': '...'
        },
    )
    self.send_event(
        "task-failed",
        # Retry sending the message if the connection is lost
        retry=True,
        exception=str(exception),
        traceback=traceback.format_exc(),
    )

    raise Ignore(str(exception))


def mark_task_as_failed_ignore(self: Any, name: str, exception: Exception) -> NoReturn:

    if TESTING:
        self.request.id = "fixed-id"
        self.request.task = name

    task_id = self.request.id
    task_name = self.request.task
    log.warning("Celery task {} ({}) failed: {}", task_id, task_name, exception)

    self.update_state(
        state=states.FAILURE,
        meta={
            "exc_type": type(exception).__name__,
            "exc_message": traceback.format_exc().split("\n"),
            # 'custom': '...'
        },
    )
    self.send_event(
        "task-failed",
        # Retry sending the message if the connection is lost
        retry=True,
        exception=str(exception),
        traceback=traceback.format_exc(),
    )

    raise exception


def mark_task_as_retriable(
    self: Any, name: str, exception: Exception, MAX_RETRIES: int
) -> NoReturn:
    if TESTING:
        self.request.id = "fixed-id"
        self.request.task = name
        self.request.retries = 0

    task_id = self.request.id
    task_name = self.request.task
    arguments = str(self.request.args)
    retry_num = 1 + self.request.retries

    # All retries attempts failed,
    # the error will be converted to permanent
    if retry_num > MAX_RETRIES:
        log.critical("MAX retries reached")
        mark_task_as_failed(self=self, name=name, exception=exception)

    # Removing username and password from urls in error stack
    clean_error_stack = ""
    for line in traceback.format_exc().split("\n"):
        clean_error_stack += f"{obfuscate_url(line)}\n"

    log.warning(
        "Celery task {} ({}) failed due to: {}, " "but will be retried (fail #{}/{})",
        task_id,
        task_name,
        exception,
        retry_num,
        MAX_RETRIES,
    )

    if Connector.check_availability("smtp"):
        log.info("Sending error report by email", task_id, task_name)
        send_celery_error_notification(
            task_id, task_name, arguments, clean_error_stack, retry_num
        )
    raise exception


class CeleryExt(Connector):
    """
    Main connector class
    """

    CELERYBEAT_SCHEDULER: Optional[str] = None
    celery_app: Celery = Celery("RAPyDo")

    # This decorator replaces:
    # - CeleryExt.celery_app.task(func, bind=True, name="{{name}}")
    # - send_errors_by_email
    # - with CeleryExt.app.app_context():
    # Use with
    # @CeleryExt.task() [to automatically use function name]
    # or: CeleryExt.task(name="your_custom_name")
    @staticmethod
    def task(
        idempotent: bool,
        name: Optional[str] = None,
        autoretry_for: Tuple[Type[Exception], ...] = tuple(),
    ) -> Callable[[F], F]:
        """
        Wrapper of the celery task decorator for a smooth integration in RAPyDo
        Parameters
        ---------
        idempotent
            A string to assign to the `name` instance attribute.
        name
            A string to assign to the `name` instance attribute.
        autoretry_for
            A string to assign to the `name` instance attribute.
        """
        # extend autoretry_for with CeleryRetryTask
        # duplicates will be removed by passing for set and tuple again
        autoretry_for = tuple(set((CeleryRetryTask,) + autoretry_for))
        MAX_RETRIES = 5

        def decorator(func: F) -> F:
            # This decorator is not covered by tests because can't be tested on backend
            # However it is tested on celery so... even if not covered it is ok
            @CeleryExt.celery_app.task(
                bind=True,
                name=name or func.__name__,
                autoretry_for=autoretry_for,
                max_retries=MAX_RETRIES,
                # autoretries will be delayed following via an exponential backoff
                retry_backoff=True,
                # retry_backoff_max=600  # default
                # used to introduce randomness into exponential backoff delays,
                # to prevent all tasks in the queue from being executed simultaneously.
                # the delay value will be a random number between zero and retry_backoff
                retry_jitter=True,
                # If enabled, messages for this task will be acknowledged after the task
                # has been executed, not just before (the default behavior).
                # This means the task may be executed multiple times if the worker
                # crashes in the middle of execution.
                # Make sure your tasks are idempotent
                acks_late=idempotent,
            )
            @wraps(func)
            def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:

                try:
                    with CeleryExt.app.app_context():
                        return func(self, *args, **kwargs)
                except Ignore as ex:

                    mark_task_as_failed_ignore(
                        self=self, name=name or func.__name__, exception=ex
                    )

                except autoretry_for as ex:

                    mark_task_as_retriable(
                        self=self,
                        name=name or func.__name__,
                        exception=ex,
                        MAX_RETRIES=MAX_RETRIES,
                    )
                except Exception as ex:

                    mark_task_as_failed(
                        self=self, name=name or func.__name__, exception=ex
                    )

            return cast(F, wrapper)

        return decorator

    @staticmethod
    def get_connection_exception() -> ExceptionsList:
        return None

    @staticmethod
    def get_rabbit_url(variables: Dict[str, str], protocol: str) -> str:
        host = variables.get("host")
        port = Env.to_int(variables.get("port"))
        vhost = variables.get("vhost", "")
        vhost = f"/{vhost}"

        user = variables.get("user", "")
        pwd = variables.get("password", "")
        creds = ""
        if user and pwd:
            creds = f"{user}:{pwd}@"

        return f"{protocol}://{creds}{host}:{port}{vhost}"

    @staticmethod
    def get_redis_url(
        variables: Dict[str, str], protocol: str, celery_beat: bool
    ) -> str:
        host = variables.get("host")
        port = Env.to_int(variables.get("port"))
        pwd = variables.get("password", "")
        creds = ""
        if pwd:
            creds = f":{pwd}@"

        if celery_beat:
            db = RedisExt.CELERY_BEAT_DB
        else:
            db = RedisExt.CELERY_DB

        return f"{protocol}://{creds}{host}:{port}/{db}"

    @staticmethod
    def get_mongodb_url(variables: Dict[str, str], protocol: str) -> str:
        host = variables.get("host")
        port = Env.to_int(variables.get("port"))
        user = variables.get("user", "")
        pwd = variables.get("password", "")

        creds = ""
        if user and pwd:
            creds = f"{user}:{pwd}@"

        return f"{protocol}://{creds}{host}:{port}"

    def connect(self, **kwargs: str) -> "CeleryExt":

        variables = self.variables.copy()
        variables.update(kwargs)
        broker = variables.get("broker_service")

        if HOST_TYPE == DOCS:  # pragma: no cover
            broker = "RABBIT"

        if broker is None:  # pragma: no cover
            print_and_exit("Unable to start Celery, missing broker service")

        if broker == "RABBIT":
            service_vars = Env.load_variables_group(prefix="rabbitmq")

            if Env.to_bool(service_vars.get("ssl_enabled")):
                # The setting can be a dict with the following keys:
                #   ssl_cert_reqs (required): one of the SSLContext.verify_mode values:
                #         ssl.CERT_NONE
                #         ssl.CERT_OPTIONAL
                #         ssl.CERT_REQUIRED
                #   ssl_ca_certs (optional): path to the CA certificate
                #   ssl_certfile (optional): path to the client certificate
                #   ssl_keyfile (optional): path to the client key

                server_hostname = RabbitExt.get_hostname(service_vars.get("host", ""))
                force_self_signed = Env.get_bool("SSL_FORCE_SELF_SIGNED")
                ca_certs = (
                    SSL_CERTIFICATE
                    if server_hostname == "localhost" or force_self_signed
                    else certifi.where()
                )
                self.celery_app.conf.broker_use_ssl = {
                    # 'keyfile': '/var/ssl/private/worker-key.pem',
                    # 'certfile': '/var/ssl/amqp-server-cert.pem',
                    # 'ca_certs': '/var/ssl/myca.pem',
                    # 'cert_reqs': ssl.CERT_REQUIRED
                    # 'cert_reqs': ssl.CERT_OPTIONAL
                    "cert_reqs": ssl.CERT_REQUIRED,
                    "server_hostname": server_hostname,
                    "ca_certs": ca_certs,
                }

            self.celery_app.conf.broker_url = self.get_rabbit_url(
                service_vars, protocol="pyamqp"
            )

        elif broker == "REDIS":
            service_vars = Env.load_variables_group(prefix="redis")

            self.celery_app.conf.broker_use_ssl = False

            self.celery_app.conf.broker_url = self.get_redis_url(
                service_vars, protocol="redis", celery_beat=False
            )

        else:  # pragma: no cover
            print_and_exit("Unable to start Celery: unknown broker service: {}", broker)

        log.info(
            "Configured {} as broker {}",
            broker,
            obfuscate_url(self.celery_app.conf.broker_url),
        )
        # From the guide: "Default: Taken from broker_url."
        # But it is not true, connection fails if not explicitly set
        self.celery_app.conf.broker_read_url = self.celery_app.conf.broker_url
        self.celery_app.conf.broker_write_url = self.celery_app.conf.broker_url

        backend = variables.get("backend_service", broker)

        if backend == "RABBIT":
            service_vars = Env.load_variables_group(prefix="rabbitmq")

            log.warning(
                "RABBIT backend is quite limited and not fully supported. "
                "Consider to enable Redis or MongoDB as a backend database"
            )
            self.celery_app.conf.result_backend = self.get_rabbit_url(
                service_vars, protocol="rpc"
            )

        elif backend == "REDIS":
            service_vars = Env.load_variables_group(prefix="redis")

            self.celery_app.conf.result_backend = self.get_redis_url(
                service_vars, protocol="redis", celery_beat=False
            )
            # set('redis_backend_use_ssl', kwargs.get('redis_backend_use_ssl'))

        elif backend == "MONGODB":
            service_vars = Env.load_variables_group(prefix="mongo")

            self.celery_app.conf.result_backend = self.get_mongodb_url(
                service_vars, protocol="mongodb"
            )

        else:  # pragma: no cover
            print_and_exit(
                "Unable to start Celery: unknown backend service: {}", backend
            )

        log.info(
            "Configured {} as backend {}",
            backend,
            obfuscate_url(self.celery_app.conf.result_backend),
        )

        # Should be enabled?
        # Default: Disabled by default (transient messages).
        # If set to True, result messages will be persistent.
        # This means the messages won’t be lost after a broker restart.
        # self.celery_app.conf.result_persistent = True

        # Skip initial warnings, avoiding pickle format (deprecated)
        self.celery_app.conf.accept_content = ["json"]
        self.celery_app.conf.task_serializer = "json"
        # Decides if publishing task messages will be retried in the case of
        # connection loss or other connection errors
        self.celery_app.conf.task_publish_retry = True
        self.celery_app.conf.result_serializer = "json"

        # Already enabled by default to use UTC
        # self.celery_app.conf.enable_utc
        # self.celery_app.conf.timezone

        # Not needed, because tasks are dynamcally injected
        # self.celery_app.conf.imports
        # self.celery_app.conf.includes

        # Note about priority: multi-queues is better than prioritized tasks
        # https://docs.celeryproject.org/en/master/faq.html#does-celery-support-task-priorities

        # Max priority default value for all queues
        # Required to be able to set priority parameter on task calls
        self.celery_app.conf.task_queue_max_priority = 10

        # Default priority for taks (if not specified)
        self.celery_app.conf.task_default_priority = 5

        # If you want to apply a more strict priority to items
        # probably prefetching should also be disabled:

        # Late ack means the task messages will be acknowledged after the task
        # has been executed, not just before (the default behavior).
        # self.celery_app.conf.task_acks_late = True

        # How many messages to prefetch at a time multiplied by the number
        # of concurrent processes. The default is 4 (four messages for each process).
        # The default setting is usually a good choice, however – if you have very
        # long running tasks waiting in the queue and you have to start the workers,
        # note that the first worker to start will receive four times the number
        # of messages initially. Thus the tasks may not be fairly distributed to
        # the workers. To disable prefetching, set worker_prefetch_multiplier to 1.
        # Changing that setting to 0 will allow the worker to keep consuming as many
        # messages as it wants.
        self.celery_app.conf.worker_prefetch_multiplier = 1

        # Introduced in Celery 5.1: on connection loss cancels all currently executed
        # tasks with late acknowledgement enabled.
        # These tasks cannot be acknowledged as the connection is gone,
        # and the tasks are automatically redelivered back to the queue.
        # In Celery 5.1 it is set to False by default.
        # The setting will be set to True by default in Celery 6.0.
        self.celery_app.conf.worker_cancel_long_running_tasks_on_connection_loss = True

        if Env.get_bool("CELERYBEAT_ENABLED"):

            CeleryExt.CELERYBEAT_SCHEDULER = backend

            if backend == "MONGODB":
                service_vars = Env.load_variables_group(prefix="mongo")
                url = self.get_mongodb_url(service_vars, protocol="mongodb")
                SCHEDULER_DB = "celery"
                self.celery_app.conf["CELERY_MONGODB_SCHEDULER_DB"] = SCHEDULER_DB
                self.celery_app.conf[
                    "CELERY_MONGODB_SCHEDULER_COLLECTION"
                ] = "schedules"
                self.celery_app.conf["CELERY_MONGODB_SCHEDULER_URL"] = url

                import mongoengine

                m = mongoengine.connect(SCHEDULER_DB, host=url)
                log.info("Celery-beat connected to MongoDB: {}", m)
            elif backend == "REDIS":

                service_vars = Env.load_variables_group(prefix="redis")
                url = self.get_redis_url(
                    service_vars, protocol="redis", celery_beat=True
                )

                self.celery_app.conf["REDBEAT_REDIS_URL"] = url
                self.celery_app.conf["REDBEAT_KEY_PREFIX"] = REDBEAT_KEY_PREFIX
                log.info("Celery-beat connected to Redis: {}", obfuscate_url(url))
            else:  # pragma: no cover
                log.warning(
                    "Cannot configure celery beat scheduler with backend: {}", backend
                )

        # self.disconnected = False

        conf = self.celery_app.conf
        # Replace the previous App with new settings
        self.celery_app = Celery(
            "RAPyDo", broker=conf.broker_url, backend=conf.result_backend
        )
        self.celery_app.conf = conf

        for funct in Meta.get_celery_tasks(f"{CUSTOM_PACKAGE}.tasks"):
            # Weird errors due to celery-stubs?
            # "Callable[[], Any]" has no attribute "register"
            # The code is correct... let's ignore it
            self.celery_app.tasks.register(funct)  # type: ignore

        return self

    def disconnect(self) -> None:
        self.disconnected = True

    def is_connected(self) -> bool:

        log.warning("celery.is_connected method is not implemented")
        return not self.disconnected

    @classmethod
    def get_periodic_task(cls, name: str) -> Any:

        if cls.CELERYBEAT_SCHEDULER == "MONGODB":
            from celerybeatmongo.models import DoesNotExist, PeriodicTask

            try:
                return PeriodicTask.objects.get(name=name)
            except DoesNotExist:
                return None
        if cls.CELERYBEAT_SCHEDULER == "REDIS":
            from redbeat.schedulers import RedBeatSchedulerEntry

            try:
                task_key = f"{REDBEAT_KEY_PREFIX}{name}"
                return RedBeatSchedulerEntry.from_key(
                    task_key, app=CeleryExt.celery_app
                )
            except KeyError:
                return None
        raise AttributeError(
            f"Unsupported celery-beat scheduler: {cls.CELERYBEAT_SCHEDULER}"
        )

    @classmethod
    def delete_periodic_task(cls, name: str) -> bool:
        t = cls.get_periodic_task(name)
        if t is None:
            return False
        t.delete()
        return True

    # period = ('days', 'hours', 'minutes', 'seconds', 'microseconds')
    @classmethod
    def create_periodic_task(
        cls,
        name: str,
        task: str,
        every: Union[str, int, timedelta],
        period: AllowedTimedeltaPeriods = "seconds",
        args: List[Any] = None,
        kwargs: Dict[str, Any] = None,
    ) -> None:
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}

        if cls.CELERYBEAT_SCHEDULER == "MONGODB":
            from celerybeatmongo.models import PeriodicTask

            PeriodicTask(
                name=name,
                task=task,
                enabled=True,
                args=args,
                kwargs=kwargs,
                interval=PeriodicTask.Interval(every=every, period=period),
            ).save()
        elif cls.CELERYBEAT_SCHEDULER == "REDIS":
            from celery.schedules import schedule
            from redbeat.schedulers import RedBeatSchedulerEntry

            # convert strings and integers to timedeltas
            if isinstance(every, str) and every.isdigit():
                every = get_timedelta(int(every), period)
            elif isinstance(every, int):
                every = get_timedelta(every, period)

            if not isinstance(every, timedelta):
                t = type(every).__name__
                raise AttributeError(
                    f"Invalid input parameter every = {every} (type {t})"
                )
            interval = schedule(run_every=every)
            entry = RedBeatSchedulerEntry(
                name, task, interval, args=args, app=CeleryExt.celery_app
            )
            entry.save()

        else:
            raise AttributeError(
                f"Unsupported celery-beat scheduler: {cls.CELERYBEAT_SCHEDULER}"
            )

    @classmethod
    def create_crontab_task(
        cls,
        name: str,
        task: str,
        minute: str,
        hour: str,
        day_of_week: str = "*",
        day_of_month: str = "*",
        month_of_year: str = "*",
        args: List[Any] = None,
        kwargs: Dict[str, Any] = None,
    ) -> None:

        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}

        if cls.CELERYBEAT_SCHEDULER == "MONGODB":
            from celerybeatmongo.models import PeriodicTask

            PeriodicTask(
                name=name,
                task=task,
                enabled=True,
                args=args,
                kwargs=kwargs,
                crontab=PeriodicTask.Crontab(
                    minute=minute,
                    hour=hour,
                    day_of_week=day_of_week,
                    day_of_month=day_of_month,
                    month_of_year=month_of_year,
                ),
            ).save()
        elif cls.CELERYBEAT_SCHEDULER == "REDIS":
            from celery.schedules import crontab
            from redbeat.schedulers import RedBeatSchedulerEntry

            interval = crontab(
                minute=minute,
                hour=hour,
                day_of_week=day_of_week,
                day_of_month=day_of_month,
                month_of_year=month_of_year,
            )

            entry = RedBeatSchedulerEntry(
                name, task, interval, args=args, app=CeleryExt.celery_app
            )
            entry.save()

        else:
            raise AttributeError(
                f"Unsupported celery-beat scheduler: {cls.CELERYBEAT_SCHEDULER}"
            )


instance = CeleryExt()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: str,
) -> "CeleryExt":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
