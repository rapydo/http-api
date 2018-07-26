# -*- coding: utf-8 -*-

"""
Celery extension wrapper

"""
from restapi.flask_ext import BaseExtension, get_logger
from celery import Celery

log = get_logger(__name__)


class CeleryExt(BaseExtension):

    celery_app = None

    def custom_connection(self, **kwargs):

        worker_mode = self.args.get("worker_mode", False)

        broker = self.variables.get("broker")

        if broker is None:
            log.exit("Unable to start Celery, missing broker service")
            # celery_app = None
            # return celery_app

        BROKER_HOST = self.variables.get("broker_host")
        BROKER_PORT = int(self.variables.get("broker_port"))
        BROKER_USER = self.variables.get("broker_user", "")
        BROKER_PASSWORD = self.variables.get("broker_password", "")
        BROKER_VHOST = self.variables.get("broker_vhost", "")

        if BROKER_USER == "":
            BROKER_USER = None
        if BROKER_PASSWORD == "":
            BROKER_PASSWORD = None

        if BROKER_VHOST != "":
            BROKER_VHOST = "/%s" % BROKER_VHOST

        backend = self.variables.get("backend", broker)
        BACKEND_HOST = self.variables.get("backend_host", BROKER_HOST)
        BACKEND_PORT = int(self.variables.get("backend_port", BROKER_PORT))
        BACKEND_USER = self.variables.get("backend_user", BROKER_USER)
        BACKEND_PASSWORD = self.variables.get(
            "backend_password", BROKER_PASSWORD)

        if BACKEND_USER == "":
            BACKEND_USER = None
        if BACKEND_PASSWORD == "":
            BACKEND_PASSWORD = None

        if BROKER_USER is not None and BROKER_PASSWORD is not None:
            BROKER_CREDENTIALS = "%s:%s@" % (BROKER_USER, BROKER_PASSWORD)
        else:
            BROKER_CREDENTIALS = ""

        if broker == 'RABBIT':
            BROKER_URL = 'amqp://%s%s%s' % (
                BROKER_CREDENTIALS, BROKER_HOST, BROKER_VHOST)
            log.info("Configured RabbitMQ as Celery broker %s", BROKER_URL)
        elif broker == 'REDIS':
            BROKER_URL = 'redis://%s%s:%s/0' % (
                BROKER_CREDENTIALS, BROKER_HOST, BROKER_PORT)
            log.info("Configured Redis as Celery broker %s", BROKER_URL)
        else:
            log.error(
                "Unable to start Celery unknown broker service: %s" % broker)
            celery_app = None
            return celery_app

        if BACKEND_USER is not None and BACKEND_PASSWORD is not None:
            BACKEND_CREDENTIALS = "%s:%s@" % (BACKEND_USER, BACKEND_PASSWORD)
        else:
            BACKEND_CREDENTIALS = ""

        if backend == 'RABBIT':
            BACKEND_URL = 'rpc://%s%s:%s/0' % (
                BACKEND_CREDENTIALS, BACKEND_HOST, BACKEND_PORT)
            log.info("Configured RabbitMQ as Celery backend %s", BACKEND_URL)
        elif backend == 'REDIS':
            BACKEND_URL = 'redis://%s%s:%s/0' % (
                BACKEND_CREDENTIALS, BACKEND_HOST, BACKEND_PORT)
            log.info("Configured Redis as Celery backend %s", BACKEND_URL)
        elif backend == 'MONGODB':
            BACKEND_URL = 'mongodb://%s%s:%s' % (
                BACKEND_CREDENTIALS, BACKEND_HOST, BACKEND_PORT)
            log.info("Configured MongoDB as Celery backend %s", BACKEND_URL)
        else:
            log.exit(
                "Unable to start Celery unknown backend service: %s" % backend)
            # celery_app = None
            # return celery_app

        celery_app = Celery(
            'RestApiQueue',
            broker=BROKER_URL,
            backend=BACKEND_URL
        )

        if not worker_mode:

            from celery.task.control import inspect
            insp = inspect()
            if not insp.stats():
                log.warning("No running Celery workers were found")

        # Skip initial warnings, avoiding pickle format (deprecated)
        celery_app.conf.accept_content = ['json']
        celery_app.conf.task_serializer = 'json'
        celery_app.conf.result_serializer = 'json'

        """
        This is a workaround, please fix me!

        This workaround is required to avoid the work be freeze when is
        the connection to rabbit is temporary lost.
        Behavious without the option:
        connection lost
        => trying to connect - repeat until the connection is back
        => once the connection is back Celery raise an exception and stops:
        ConnectionResetError: [Errno 104] Connection reset by peer

        broker_pool_limit = None means that the connection pool is disabled
        and connections will be established and closed for every use
        I found this workaround here:

        https://github.com/celery/celery/issues/4226
        """
        # celery_app.conf.broker_pool_limit = None

        if CeleryExt.celery_app is None:
            CeleryExt.celery_app = celery_app

        return celery_app
