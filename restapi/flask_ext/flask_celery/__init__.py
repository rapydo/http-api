# -*- coding: utf-8 -*-

"""
Celery extension wrapper

"""
from celery import Celery
from functools import wraps
import traceback

from restapi.services.mail import send_mail_is_active, send_mail
from restapi.flask_ext import BaseExtension
from restapi.confs import get_project_configuration

from restapi.utilities.logs import log, obfuscate_url


class CeleryExt(BaseExtension):

    CELERY_BEAT_SCHEDULER = None
    REDBEAT_KEY_PREFIX = "redbeat:"
    celery_app = None

    def custom_connection(self, **kwargs):

        # set here to avoid warnings like 'Possible hardcoded password'
        EMPTY = ""

        broker = self.variables.get("broker")

        if broker is None:
            log.exit("Unable to start Celery, missing broker service")
            # celery_app = None
            # return celery_app

        # Do not import before loading the ext!
        from restapi.services.detect import Detector

        if broker == 'RABBIT':
            service_vars = Detector.load_variables({'prefix': 'rabbitmq'})
            BROKER_HOST = service_vars.get("host")
            BROKER_PORT = int(service_vars.get("port"))
            BROKER_USER = service_vars.get("user", "")
            BROKER_PASSWORD = service_vars.get("password", "")
            BROKER_VHOST = service_vars.get("vhost", "")
            BROKER_USE_SSL = Detector.get_bool_envvar(
                service_vars.get("ssl_enabled", False)
            )
        elif broker == 'REDIS':
            service_vars = Detector.load_variables({'prefix': 'redis'})
            BROKER_HOST = service_vars.get("host")
            BROKER_PORT = int(service_vars.get("port"))
            BROKER_USER = None
            BROKER_PASSWORD = None
            BROKER_VHOST = ""
            BROKER_USE_SSL = False
        else:
            log.exit("Invalid celery broker: {}", broker)

        if BROKER_USER == "":
            BROKER_USER = None
        if BROKER_PASSWORD == EMPTY:
            BROKER_PASSWORD = None

        if BROKER_VHOST != "":
            BROKER_VHOST = "/{}".format(BROKER_VHOST)

        if BROKER_USER is not None and BROKER_PASSWORD is not None:
            BROKER_CREDENTIALS = '{}:{}@'.format(BROKER_USER, BROKER_PASSWORD)
        else:
            BROKER_CREDENTIALS = ""

        if broker == 'RABBIT':
            BROKER_URL = 'amqp://{}{}:{}{}'.format(
                BROKER_CREDENTIALS,
                BROKER_HOST,
                BROKER_PORT,
                BROKER_VHOST,
            )
            log.info(
                "Configured RabbitMQ as Celery broker {}", obfuscate_url(BROKER_URL))
        elif broker == 'REDIS':
            BROKER_URL = 'redis://{}{}:{}/0'.format(
                BROKER_CREDENTIALS,
                BROKER_HOST,
                BROKER_PORT,
            )
            log.info(
                "Configured Redis as Celery broker {}", obfuscate_url(BROKER_URL))
        else:
            log.error("Unable to start Celery unknown broker service: {}", broker)
            celery_app = None
            return celery_app

        backend = self.variables.get("backend", broker)

        if backend == 'RABBIT':
            service_vars = Detector.load_variables({'prefix': 'rabbitmq'})
            BACKEND_HOST = service_vars.get("host")
            BACKEND_PORT = int(service_vars.get("port"))
            BACKEND_USER = service_vars.get("user", "")
            BACKEND_PASSWORD = service_vars.get("password", "")
        elif backend == 'REDIS':
            service_vars = Detector.load_variables({'prefix': 'redis'})
            BACKEND_HOST = service_vars.get("host")
            BACKEND_PORT = int(service_vars.get("port"))
            BACKEND_USER = ""
            BACKEND_PASSWORD = None
        elif backend == 'MONGODB':
            service_vars = Detector.load_variables({'prefix': 'mongo'})
            BACKEND_HOST = service_vars.get("host")
            BACKEND_PORT = int(service_vars.get("port"))
            BACKEND_USER = service_vars.get("user", "")
            BACKEND_PASSWORD = service_vars.get("password", "")
        else:
            log.exit("Invalid celery backend: {}", backend)

        if BACKEND_USER == EMPTY:
            BACKEND_USER = None
        if BACKEND_PASSWORD == EMPTY:
            BACKEND_PASSWORD = None

        if BACKEND_USER is not None and BACKEND_PASSWORD is not None:
            BACKEND_CREDENTIALS = '{}:{}@'.format(BACKEND_USER, BACKEND_PASSWORD)
        else:
            BACKEND_CREDENTIALS = ""

        if backend == 'RABBIT':
            BACKEND_URL = 'rpc://{}{}:{}/0'.format(
                BACKEND_CREDENTIALS,
                BACKEND_HOST,
                BACKEND_PORT,
            )
            log.info(
                "Configured RabbitMQ as Celery backend {}", obfuscate_url(BACKEND_URL))
        elif backend == 'REDIS':
            BACKEND_URL = 'redis://{}{}:{}/0'.format(
                BACKEND_CREDENTIALS,
                BACKEND_HOST,
                BACKEND_PORT,
            )
            log.info(
                "Configured Redis as Celery backend {}", obfuscate_url(BACKEND_URL))
        elif backend == 'MONGODB':
            BACKEND_URL = 'mongodb://{}{}:{}'.format(
                BACKEND_CREDENTIALS,
                BACKEND_HOST,
                BACKEND_PORT,
            )
            log.info(
                "Configured MongoDB as Celery backend {}", obfuscate_url(BACKEND_URL))
        else:
            log.exit("Unable to start Celery unknown backend service: {}", backend)
            # celery_app = None
            # return celery_app

        celery_app = Celery('RestApiQueue', broker=BROKER_URL, backend=BACKEND_URL)
        celery_app.conf['broker_use_ssl'] = BROKER_USE_SSL

        # if not worker_mode:

        #     from celery.task.control import inspect

        #     insp = inspect()
        #     if not insp.stats():
        #         log.warning("No running Celery workers were found")

        # Skip initial warnings, avoiding pickle format (deprecated)
        celery_app.conf.accept_content = ['json']
        celery_app.conf.task_serializer = 'json'
        celery_app.conf.result_serializer = 'json'
        # Max priority default value for all queues
        # Required to be able to set priority parameter on apply_async calls
        # celery_app.conf.task_queue_max_priority = 10

        # default_exchange = Exchange('default', type='direct')
        # priority_exchange = Exchange('priority', type='direct')
        # celery_app.conf.task_queues = [
        #     Queue(
        #         'priority',
        #         priority_exchange,
        #         routing_key='priority',
        #         queue_arguments={
        #             'x-max-priority': 10
        #         }
        #     )
        # ]
        # If you want to apply a more strict priority to items
        # probably prefetching should also be disabled:

        # CELERY_ACKS_LATE = True
        # CELERYD_PREFETCH_MULTIPLIER = 1

        # celery_app.conf.broker_pool_limit = None

        if Detector.get_bool_from_os('CELERY_BEAT_ENABLED'):

            CeleryExt.CELERY_BEAT_SCHEDULER = backend

            if backend == 'MONGODB':
                SCHEDULER_DB = 'celery'
                celery_app.conf['CELERY_MONGODB_SCHEDULER_DB'] = SCHEDULER_DB
                celery_app.conf['CELERY_MONGODB_SCHEDULER_COLLECTION'] = "schedules"
                celery_app.conf['CELERY_MONGODB_SCHEDULER_URL'] = BACKEND_URL

                import mongoengine

                m = mongoengine.connect(SCHEDULER_DB, host=BACKEND_URL)
                log.info("Celery-beat connected to MongoDB: {}", m)
            elif backend == 'REDIS':

                BEAT_BACKEND_URL = 'redis://{}{}:{}/1'.format(
                    BACKEND_CREDENTIALS,
                    BACKEND_HOST,
                    BACKEND_PORT,
                )

                celery_app.conf['REDBEAT_REDIS_URL'] = BEAT_BACKEND_URL
                celery_app.conf['REDBEAT_KEY_PREFIX'] = CeleryExt.REDBEAT_KEY_PREFIX
                log.info("Celery-beat connected to Redis: {}", BEAT_BACKEND_URL)
            else:
                log.warning("Cannot configure celery beat scheduler")

        if CeleryExt.celery_app is None:
            CeleryExt.celery_app = celery_app

        return celery_app

    @classmethod
    def get_periodic_task(cls, name):

        if cls.CELERY_BEAT_SCHEDULER == 'MONGODB':
            from celerybeatmongo.models import PeriodicTask, DoesNotExist
            try:
                return PeriodicTask.objects.get(name=name)
            except DoesNotExist:
                return None
        elif cls.CELERY_BEAT_SCHEDULER == 'REDIS':
            from redbeat.schedulers import RedBeatSchedulerEntry
            try:
                task_key = "{}{}".format(cls.REDBEAT_KEY_PREFIX, name)
                return RedBeatSchedulerEntry.from_key(
                    task_key, app=CeleryExt.celery_app)
            except KeyError:
                return None
        else:
            log.error(
                "Unsupported celery-beat scheduler: {}", cls.CELERY_BEAT_SCHEDULER)

    @classmethod
    def delete_periodic_task(cls, name):
        t = cls.get_periodic_task(name)
        if t is None:
            return False
        t.delete()
        return True

    # period = ('days', 'hours', 'minutes', 'seconds', 'microseconds')
    @classmethod
    def create_periodic_task(cls, name, task, every,
                             period='seconds', args=[], kwargs={}):

        if cls.CELERY_BEAT_SCHEDULER == 'MONGODB':
            from celerybeatmongo.models import PeriodicTask
            PeriodicTask(
                name=name,
                task=task,
                enabled=True,
                args=args,
                kwargs=kwargs,
                interval=PeriodicTask.Interval(every=every, period=period),
            ).save()
        elif cls.CELERY_BEAT_SCHEDULER == 'REDIS':
            from celery.schedules import schedule
            from redbeat.schedulers import RedBeatSchedulerEntry
            if period != 'seconds':

                # do conversion... run_every should be a datetime.timedelta
                log.error("Unsupported period {} for redis beat", period)

            interval = schedule(run_every=every)  # seconds
            entry = RedBeatSchedulerEntry(
                name,
                task,
                interval,
                args=args,
                app=CeleryExt.celery_app
            )
            entry.save()

        else:
            log.error(
                "Unsupported celery-beat scheduler: {}", cls.CELERY_BEAT_SCHEDULER)

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
        args=[],
        kwargs={},
    ):

        if cls.CELERY_BEAT_SCHEDULER == 'MONGODB':
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
        elif cls.CELERY_BEAT_SCHEDULER == 'REDIS':
            from celery.schedules import crontab
            from redbeat.schedulers import RedBeatSchedulerEntry
            interval = crontab(
                minute=minute,
                hour=hour,
                day_of_week=day_of_week,
                day_of_month=day_of_month,
                month_of_year=month_of_year
            )

            entry = RedBeatSchedulerEntry(
                name,
                task,
                interval,
                args=args,
                app=CeleryExt.celery_app
            )
            entry.save()

        else:
            log.error(
                "Unsupported celery-beat scheduler: {}", cls.CELERY_BEAT_SCHEDULER)


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

            if send_mail_is_active():
                log.info("Sending error report by email", task_id, task_name)

                body = """
Celery task {} failed

Name: {}

Arguments: {}

Error: {}
""".format(task_id, task_name, str(self.request.args), traceback.format_exc())

                project = get_project_configuration(
                    "project.title",
                    default='Unkown title',
                )
                subject = "{}: task {} failed".format(project, task_name)
                send_mail(body, subject)

    return wrapper
