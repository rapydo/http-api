import traceback
from datetime import timedelta
from functools import wraps

from celery import Celery

from restapi.confs import CUSTOM_PACKAGE, get_project_configuration
from restapi.connectors import Connector
from restapi.env import Env
from restapi.utilities.logs import log, obfuscate_url
from restapi.utilities.meta import Meta


class CeleryExt(Connector):

    CELERYBEAT_SCHEDULER = None
    REDBEAT_KEY_PREFIX = "redbeat:"
    celery_app = None

    def get_connection_exception(self):
        return None

    def connect(self, **kwargs):

        # set here to avoid warnings like 'Possible hardcoded password'
        EMPTY = ""

        variables = self.variables.copy()
        variables.update(kwargs)
        broker = variables.get("broker")

        if broker is None:  # pragma: no cover
            log.exit("Unable to start Celery, missing broker service")

        # Do not import before loading the ext!
        from restapi.services.detect import Detector

        if broker == "RABBIT":
            service_vars = Detector.load_variables(prefix="rabbitmq")
            BROKER_HOST = service_vars.get("host")
            BROKER_PORT = Env.to_int(service_vars.get("port"))
            BROKER_USER = service_vars.get("user", "")
            BROKER_PASSWORD = service_vars.get("password", "")
            BROKER_VHOST = service_vars.get("vhost", "")
            BROKER_USE_SSL = Env.to_bool(service_vars.get("ssl_enabled"))

        elif broker == "REDIS":
            service_vars = Detector.load_variables(prefix="redis")
            BROKER_HOST = service_vars.get("host")
            BROKER_PORT = Env.to_int(service_vars.get("port"))
            BROKER_USER = None
            BROKER_PASSWORD = None
            BROKER_VHOST = ""
            BROKER_USE_SSL = False
        else:  # pragma: no cover
            log.exit("Invalid celery broker: {}", broker)

        if BROKER_USER == "":  # pragma: no cover
            BROKER_USER = None
        if BROKER_PASSWORD == EMPTY:  # pragma: no cover
            BROKER_PASSWORD = None

        if BROKER_VHOST != "":
            BROKER_VHOST = f"/{BROKER_VHOST}"

        if BROKER_USER is not None and BROKER_PASSWORD is not None:
            BROKERCRED = f"{BROKER_USER}:{BROKER_PASSWORD}@"
        else:
            BROKERCRED = ""

        if broker == "RABBIT":
            BROKER_URL = f"amqp://{BROKERCRED}{BROKER_HOST}:{BROKER_PORT}{BROKER_VHOST}"
            log.info("Configured RabbitMQ as broker {}", obfuscate_url(BROKER_URL))
        elif broker == "REDIS":
            BROKER_URL = f"redis://{BROKERCRED}{BROKER_HOST}:{BROKER_PORT}/0"
            log.info("Configured Redis as broker {}", obfuscate_url(BROKER_URL))
        else:  # pragma: no cover
            log.error("Unable to start Celery: unknown broker service: {}", broker)
            return None

        backend = variables.get("backend", broker)

        if backend == "RABBIT":
            service_vars = Detector.load_variables(prefix="rabbitmq")
            BACKEND_HOST = service_vars.get("host")
            BACKEND_PORT = Env.to_int(service_vars.get("port"))
            BACKEND_USER = service_vars.get("user", "")
            BACKEND_PASSWORD = service_vars.get("password", "")
        elif backend == "REDIS":
            service_vars = Detector.load_variables(prefix="redis")
            BACKEND_HOST = service_vars.get("host")
            BACKEND_PORT = Env.to_int(service_vars.get("port"))
            BACKEND_USER = ""
            BACKEND_PASSWORD = None
        elif backend == "MONGODB":
            service_vars = Detector.load_variables(prefix="mongo")
            BACKEND_HOST = service_vars.get("host")
            BACKEND_PORT = Env.to_int(service_vars.get("port"))
            BACKEND_USER = service_vars.get("user", "")
            BACKEND_PASSWORD = service_vars.get("password", "")
        else:  # pragma: no cover
            log.exit("Invalid celery backend: {}", backend)

        if BACKEND_USER == EMPTY:
            BACKEND_USER = None
        if BACKEND_PASSWORD == EMPTY:
            BACKEND_PASSWORD = None

        if BACKEND_USER is not None and BACKEND_PASSWORD is not None:
            BACKENDCRED = f"{BACKEND_USER}:{BACKEND_PASSWORD}@"
        else:
            BACKENDCRED = ""

        if backend == "RABBIT":
            BACKEND_URL = f"rpc://{BACKENDCRED}{BACKEND_HOST}:{BACKEND_PORT}/0"
            log.info("Configured RabbitMQ as backend {}", obfuscate_url(BACKEND_URL))
        elif backend == "REDIS":
            BACKEND_URL = f"redis://{BACKENDCRED}{BACKEND_HOST}:{BACKEND_PORT}/0"
            log.info("Configured Redis as backend {}", obfuscate_url(BACKEND_URL))
        elif backend == "MONGODB":
            BACKEND_URL = f"mongodb://{BACKENDCRED}{BACKEND_HOST}:{BACKEND_PORT}"
            log.info("Configured MongoDB as backend {}", obfuscate_url(BACKEND_URL))
        else:  # pragma: no cover
            log.exit("Unable to start Celery unknown backend service: {}", backend)

        celery_app = Celery("RestApiQueue", broker=BROKER_URL, backend=BACKEND_URL)
        celery_app.conf["broker_use_ssl"] = BROKER_USE_SSL

        # Skip initial warnings, avoiding pickle format (deprecated)
        celery_app.conf.accept_content = ["json"]
        celery_app.conf.task_serializer = "json"
        celery_app.conf.result_serializer = "json"

        # Max priority default value for all queues
        # Required to be able to set priority parameter on apply_async calls
        celery_app.conf.task_queue_max_priority = 10

        # Default priority for taks (if not specified)
        celery_app.conf.task_default_priority = 5

        # If you want to apply a more strict priority to items
        # probably prefetching should also be disabled:

        # Late ack means the task messages will be acknowledged after the task
        # has been executed, not just before (the default behavior).
        # celery_app.conf.task_acks_late = True

        # How many messages to prefetch at a time multiplied by the number
        # of concurrent processes. The default is 4 (four messages for each process).
        # The default setting is usually a good choice, however – if you have very
        # long running tasks waiting in the queue and you have to start the workers,
        # note that the first worker to start will receive four times the number
        # of messages initially. Thus the tasks may not be fairly distributed to
        # the workers. To disable prefetching, set worker_prefetch_multiplier to 1.
        # Changing that setting to 0 will allow the worker to keep consuming as many
        # messages as it wants.
        celery_app.conf.worker_prefetch_multiplier = 1

        # celery_app.conf.broker_pool_limit = None

        if Env.get_bool("CELERYBEAT_ENABLED"):

            CeleryExt.CELERYBEAT_SCHEDULER = backend

            if backend == "MONGODB":
                SCHEDULER_DB = "celery"
                celery_app.conf["CELERY_MONGODB_SCHEDULER_DB"] = SCHEDULER_DB
                celery_app.conf["CELERY_MONGODB_SCHEDULER_COLLECTION"] = "schedules"
                celery_app.conf["CELERY_MONGODB_SCHEDULER_URL"] = BACKEND_URL

                import mongoengine

                m = mongoengine.connect(SCHEDULER_DB, host=BACKEND_URL)
                log.info("Celery-beat connected to MongoDB: {}", m)
            elif backend == "REDIS":

                BEATBACKENDURL = f"redis://{BACKENDCRED}{BACKEND_HOST}:{BACKEND_PORT}/1"
                celery_app.conf["REDBEAT_REDIS_URL"] = BEATBACKENDURL
                celery_app.conf["REDBEAT_KEY_PREFIX"] = CeleryExt.REDBEAT_KEY_PREFIX
                log.info("Celery-beat connected to Redis: {}", BEATBACKENDURL)
            else:
                log.warning(
                    "Cannot configure celery beat scheduler with backend: {}", backend
                )

        if CeleryExt.celery_app is None:
            CeleryExt.celery_app = celery_app

        self.celery_app = celery_app

        task_package = f"{CUSTOM_PACKAGE}.tasks"

        tasks = Meta.get_celery_tasks(task_package)

        for func_name, funct in tasks.items():
            setattr(self, func_name, funct)

        return self

    def disconnect(self):
        self.celery_app.disconnected = True
        return

    @classmethod
    def get_periodic_task(cls, name):

        if cls.CELERYBEAT_SCHEDULER == "MONGODB":
            from celerybeatmongo.models import DoesNotExist, PeriodicTask

            try:
                return PeriodicTask.objects.get(name=name)
            except DoesNotExist:
                return None
        if cls.CELERYBEAT_SCHEDULER == "REDIS":
            from redbeat.schedulers import RedBeatSchedulerEntry

            try:
                task_key = f"{cls.REDBEAT_KEY_PREFIX}{name}"
                return RedBeatSchedulerEntry.from_key(
                    task_key, app=CeleryExt.celery_app
                )
            except KeyError:
                return None
        raise AttributeError(
            f"Unsupported celery-beat scheduler: {cls.CELERYBEAT_SCHEDULER}"
        )

    @classmethod
    def delete_periodic_task(cls, name):
        t = cls.get_periodic_task(name)
        if t is None:
            return False
        t.delete()
        return True

    # period = ('days', 'hours', 'minutes', 'seconds', 'microseconds')
    @classmethod
    def create_periodic_task(
        cls, name, task, every, period="seconds", args=None, kwargs=None
    ):
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

            if period != "seconds":

                # do conversion... run_every should be a datetime.timedelta
                log.error("Unsupported period {} for redis beat", period)
                raise AttributeError(f"Unsupported period {period} for redis beat")

            # convert string to timedelta
            if isinstance(every, str) and every.isdigit():
                every = timedelta(seconds=int(every))
            elif isinstance(every, int):
                every = timedelta(seconds=every)

            if not isinstance(every, timedelta):
                t = type(every).__name__
                raise AttributeError(
                    f"Invalid input parameter every = {every} (type {t})"
                )
            interval = schedule(run_every=every)  # seconds
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
        name,
        task,
        minute,
        hour,
        day_of_week="*",
        day_of_month="*",
        month_of_year="*",
        args=None,
        kwargs=None,
    ):

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

            from restapi.services.detect import detector

            if detector.check_availability("smtp"):
                log.info("Sending error report by email", task_id, task_name)

                body = f"""
Celery task {task_id} failed

Name: {task_name}

Arguments: {self.request.args}

Error: {traceback.format_exc()}
"""

                project = get_project_configuration(
                    "project.title", default="Unkown title",
                )
                subject = f"{project}: task {task_name} failed"
                smtp = detector.get_service_instance("smtp")
                smtp.send(body, subject)

    return wrapper
