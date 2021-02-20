import traceback
from datetime import timedelta
from functools import wraps
from typing import Any, Dict, List, Optional, Union

from celery import Celery

from restapi.config import CUSTOM_PACKAGE, get_project_configuration
from restapi.connectors import Connector
from restapi.env import Env
from restapi.utilities import print_and_exit
from restapi.utilities.logs import log, obfuscate_url
from restapi.utilities.meta import Meta
from restapi.utilities.time import AllowedTimedeltaPeriods, get_timedelta

REDBEAT_KEY_PREFIX: str = "redbeat:"


class CeleryExt(Connector):

    CELERYBEAT_SCHEDULER: Optional[str] = None
    celery_app: Celery = Celery("RAPyDo")

    def get_connection_exception(self):
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
    def get_redis_url(variables: Dict[str, str], protocol: str) -> str:
        host = variables.get("host")
        port = Env.to_int(variables.get("port"))
        pwd = variables.get("password", "")
        creds = ""
        if pwd:
            creds = f":{pwd}@"

        return f"{protocol}://{creds}{host}:{port}/0"

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

    def connect(self, **kwargs):

        variables = self.variables.copy()
        variables.update(kwargs)
        broker = variables.get("broker")

        if broker is None:  # pragma: no cover
            print_and_exit("Unable to start Celery, missing broker service")

        if broker == "RABBIT":
            service_vars = Env.load_variables_group(prefix="rabbitmq")

            self.celery_app.conf.broker_use_ssl = Env.to_bool(
                service_vars.get("ssl_enabled")
            )

            self.celery_app.conf.broker_url = self.get_rabbit_url(
                service_vars, protocol="amqp"
            )

        elif broker == "REDIS":
            service_vars = Env.load_variables_group(prefix="redis")

            self.celery_app.conf.broker_use_ssl = False

            self.celery_app.conf.broker_url = self.get_redis_url(
                service_vars, protocol="redis"
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

        backend = variables.get("backend", broker)

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
                service_vars, protocol="redis"
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
        self.celery_app.conf.result_serializer = "json"

        # Already enabled by default to use UTC
        # self.celery_app.conf.enable_utc
        # self.celery_app.conf.timezone

        # Not needed, because tasks are dynamcally injected
        # self.celery_app.conf.imports
        # self.celery_app.conf.includes

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
                url = self.get_redis_url(service_vars, protocol="redis")

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
            "RAPyDo", broker=conf["broker_url"], backend=conf["result_backend"]
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


def send_errors_by_email(func):
    """
    Send a notification email to a given recipient to the
    system administrator with details about failure.
    """

    @wraps(func)
    def wrapper(self, *args, **kwargs):

        try:
            return func(self, *args, **kwargs)

        except BaseException:

            task_id = self.request.id
            task_name = self.request.task

            log.error("Celery task {} failed ({})", task_id, task_name)
            arguments = str(self.request.args)
            log.error("Failed task arguments: {}", arguments[0:256])
            log.error("Task error: {}", traceback.format_exc())

            if Connector.check_availability("smtp"):
                log.info("Sending error report by email", task_id, task_name)

                body = f"""
Celery task {task_id} failed

Name: {task_name}

Arguments: {self.request.args}

Error: {traceback.format_exc()}
"""

                project = get_project_configuration(
                    "project.title",
                    default="Unkown title",
                )
                subject = f"{project}: task {task_name} failed"
                from restapi.connectors import smtp

                smtp_client = smtp.get_instance()
                smtp_client.send(body, subject)

    return wrapper


instance = CeleryExt()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: Union[Optional[str], int],
) -> "CeleryExt":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
