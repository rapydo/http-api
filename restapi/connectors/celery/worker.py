"""
Celery pattern. Some interesting read here:

http://blog.miguelgrinberg.com/post/celery-and-the-flask-application-factory-pattern

Of course that discussion is not enough for
a flask templating framework like ours.
So we made some improvement along the code.

"""
from restapi.server import create_app
from restapi.services.detect import detector
from restapi.utilities.logs import log

################################################
# Reload Flask app code also for the worker
# This is necessary to have the app context available
app = create_app(worker_mode=True)

celery_app = detector.get_connector("celery").celery_app
celery_app.app = app


def get_service(service, **kwargs):
    return detector.get_service_instance(service, **kwargs)


celery_app.get_service = get_service

log.debug("Celery worker is ready {}", celery_app)
