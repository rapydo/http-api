from restapi.connectors import celery
from restapi.server import ServerModes, create_app
from restapi.utilities.logs import log

instance = celery.get_instance()
# Used by Celery to run the instance (--app app)
celery_app = instance.celery_app

# Reload Flask app code for the worker (needed to have the app context available)
celery.CeleryExt.app = create_app(mode=ServerModes.WORKER)

log.debug("Celery worker is ready {}", celery_app)
