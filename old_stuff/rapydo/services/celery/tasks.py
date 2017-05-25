# -*- coding: utf-8 -*-

"""

Tasks queued for asynchronous operations.

This service is quite anonymous.
I use the Celery class and farm just to make sure
that we tie the celery application to Flask,
and to check the connection at initialization time.

How to add a task:

@celery_app.task
def my_async_task(arg):
    log.debug("This is asynchronous: %s" % arg)

"""

from rapydo.services.celery.celery import celery_app
from rapydo.services import ServiceFarm, ServiceObject
from rapydo.utils.logs import get_logger

log = get_logger(__name__)


class MyCelery(ServiceObject):

    def __init__(self, app):
        self._current = self.make_celery(app)

    @staticmethod
    def get_service(service_name):
        from rapydo.utils.globals import mem
        from rapydo.services import get_instance_from_services
        return get_instance_from_services(mem.services, service_name)

    def make_celery(self, app):
        """
        Following the snippet on:
        http://flask.pocoo.org/docs/0.11/patterns/celery/
        """

        # print("SETTING APP", hex(id(app)))
        celery_app.conf.update(app.config)
        TaskBase = celery_app.Task

        class ContextTask(TaskBase):
            abstract = True

            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return TaskBase.__call__(self, *args, **kwargs)

        # Inject objects into celery
        celery_app.Task = ContextTask
        celery_app.app = app
        celery_app.get_service = self.get_service

        return celery_app


class CeleryFarm(ServiceFarm):

    _celery_app = None

    @staticmethod
    def define_service_name():
        return 'celery'

    def init_connection(self, app):

        # TOFIX: should we check also the REDIS connection?
        # Or is celery going to give us error if that does not work?

        celery = self.get_instance(app)
        log.debug("Celery queue is available")
        return celery

    @classmethod
    def get_instance(cls, app=None):

        if CeleryFarm._celery_app is None:
            CeleryFarm._celery_app = MyCelery(app)._current
        return CeleryFarm._celery_app
