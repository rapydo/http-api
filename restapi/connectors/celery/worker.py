from restapi.connectors import celery
from restapi.server import ServerModes, create_app
from restapi.utilities.logs import log

# Used by Celery to run the instance (-A app)

celery_app = celery.get_instance().celery_app

# Reload Flask app code for the worker (needed to have the app context available)
celery_app.app = create_app(mode=ServerModes.WORKER)

log.debug("Celery worker is ready {}", celery_app)
