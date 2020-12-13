"""
Celery pattern. Some interesting read here:

http://blog.miguelgrinberg.com/post/celery-and-the-flask-application-factory-pattern

Of course that discussion is not enough for
a flask templating framework like ours.
So we made some improvement along the code.

"""
from restapi.connectors.celery import CeleryExt
from restapi.server import ServerModes, create_app
from restapi.utilities.logs import log

################################################
# Reload Flask app code also for the worker
# This is necessary to have the app context available
CeleryExt.celery_app.app = create_app(mode=ServerModes.WORKER)

log.debug("Celery worker is ready")
