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

        backend = self.variables.get("backend", broker)
        BACKEND_HOST = self.variables.get("backend_host", BROKER_HOST)
        BACKEND_PORT = int(self.variables.get("backend_port", BROKER_PORT))

        if broker == 'RABBIT':
            BROKER_URL = 'amqp://%s' % (BROKER_HOST)
            log.info("Configured RabbitMQ as Celery broker %s", BROKER_URL)
        elif broker == 'REDIS':
            BROKER_URL = 'redis://%s:%s/0' % (BROKER_HOST, BROKER_PORT)
            log.info("Configured Redis as Celery broker %s", BROKER_URL)
        else:
            log.error(
                "Unable to start Celery unknown broker service: %s" % broker)
            celery_app = None
            return celery_app

        if backend == 'RABBIT':
            BACKEND_URL = 'rpc://%s:%s/0' % (BACKEND_HOST, BACKEND_PORT)
            log.info("Configured RabbitMQ as Celery backend %s", BACKEND_URL)
        elif backend == 'REDIS':
            BACKEND_URL = 'redis://%s:%s/0' % (BACKEND_HOST, BACKEND_PORT)
            log.info("Configured Redis as Celery backend %s", BACKEND_URL)
        elif backend == 'MONGODB':
            BACKEND_URL = 'mongodb://%s:%s' % (BACKEND_HOST, BACKEND_PORT)
            log.info("Configured MongoDB as Celery backend %s", BACKEND_URL)
        else:
            log.exit(
                "Unable to start Celery unknown backend service: %s" % backend)
            # celery_app = None
            # return celery_app

        celery_app = Celery(
            'RestApiQueue',
            backend=BACKEND_URL,
            broker=BROKER_URL,
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

        if CeleryExt.celery_app is None:
            CeleryExt.celery_app = celery_app

        return celery_app
