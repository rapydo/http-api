"""
Celery pattern. Some interesting read here:

http://blog.miguelgrinberg.com/post/celery-and-the-flask-application-factory-pattern

Of course that discussion is not enough for
a flask templating framework like ours.
So we made some improvement along the code.

"""

from flask import Flask

from restapi.connectors import celery
from restapi.services.detect import detector
from restapi.utilities.logs import log

app = Flask("beat")

# Explicit init_services is needed because the app is created directly from Flask
# instead of using the create_app method from server
detector.init_services(app=app, project_init=False, project_clean=False)

# Used by Celery to run the instance (-A app)
celery_app = celery.get_instance().celery_app

# Reload Flask app code for the worker (needed to have the app context available)
celery_app.app = app


log.debug("Celery beat is ready {}", celery_app)
