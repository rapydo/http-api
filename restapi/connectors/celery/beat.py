"""
Celery pattern. Some interesting read here:

http://blog.miguelgrinberg.com/post/celery-and-the-flask-application-factory-pattern

Of course that discussion is not enough for
a flask templating framework like ours.
So we made some improvement along the code.

"""

from flask import Flask

from restapi.connectors import Connector, celery
from restapi.utilities.logs import log

app = Flask("beat")

# Explicit init_app is needed because the app is created directly from Flask
# instead of using the create_app method from server
Connector.init_app(app=app)

instance = celery.get_instance()
# Used by Celery to run the instance (--app app)
celery_app = instance.celery_app

# Reload Flask app code for the worker (needed to have the app context available)
celery.CeleryExt.app = app


log.debug("Celery beat is ready {}", celery_app)
