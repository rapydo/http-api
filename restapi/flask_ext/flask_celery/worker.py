# -*- coding: utf-8 -*-

"""
Celery pattern. Some interesting read here:

http://blog.miguelgrinberg.com/post/celery-and-the-flask-application-factory-pattern

Of course that discussion is not enough for
a flask templating framework like ours.
So we made some improvement along the code.

"""

from restapi.server import create_app
from utilities import CUSTOM_PACKAGE
from utilities.meta import Meta
from utilities.logs import get_logger

log = get_logger(__name__)

################################################
# Reload Flask app code also for the worker
# This is necessary to have the app context available
app = create_app(worker_mode=True)

celery_app = app.extensions.get('celery').celery_app
celery_app.app = app


def get_service(service, **kwargs):
    return celery_app.app.extensions.get(service).get_instance(**kwargs)


celery_app.get_service = get_service

################################################
# Import tasks modules to make sure all tasks are available

meta = Meta()
# main_package = "commons.tasks."
# # Base tasks
# submodules = meta.import_submodules_from_package(main_package + "base")
# # Custom tasks
submodules = meta.import_submodules_from_package("%s.tasks" % CUSTOM_PACKAGE)

log.debug("Celery worker is ready %s", celery_app)
