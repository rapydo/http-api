# -*- coding: utf-8 -*-

"""
Celery extension wrapper

"""
from rapydo.flask_ext import BaseExtension, get_logger
from celery import Celery

log = get_logger(__name__)


class CeleryExt(BaseExtension):

    celery_app = None

    def custom_connection(self, **kwargs):

        worker_mode = self.args.get("worker_mode", False)

        broker = self.variables.get("broker")

        if broker is None:
            broker = "UNKNOWN"

        HOST = self.variables.get("broker_host")
        PORT = int(self.variables.get("broker_port"))
        if broker == 'RABBIT':

            # BROKER_URL = 'amqp://guest:guest@%s:%s/0' % (HOST, PORT)
            # BROKER_URL = 'amqp://%s:%s' % (HOST, PORT)

            # This url is equivalent to:
            # 'amqp://%s:5672/' % (HOST)
            # where / is the vhost, as obtained in rabbit container executing:
            # rabbitmqctl list_vhosts
            # Listing vhosts ...
            # /
            # See http://stackoverflow.com/questions/26624263/
            #                   celery-didnt-operate-well-because-of-errno-104

            BROKER_URL = 'amqp://%s' % (HOST)
            BACKEND_URL = 'rpc://%s:%s/0' % (HOST, PORT)
            log.info("Found RabbitMQ as Celery broker %s" % BROKER_URL)
        elif broker == 'REDIS':
            BROKER_URL = 'redis://%s:%s/0' % (HOST, PORT)
            BACKEND_URL = 'redis://%s:%s/0' % (HOST, PORT)
            log.info("Found Redis as Celery broker %s" % BROKER_URL)
        else:
            log.error("Unable to start Celery, missing broker service")
            celery_app = None
            return celery_app

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
        celery_app.conf.CELERY_ACCEPT_CONTENT = ['json']
        celery_app.conf.CELERY_TASK_SERIALIZER = 'json'
        celery_app.conf.CELERY_RESULT_SERIALIZER = 'json'

        if CeleryExt.celery_app is None:
            CeleryExt.celery_app = celery_app

        return celery_app
