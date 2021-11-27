"""
The Main server factory.
We create all the internal flask components here.
"""
import logging
import os
import signal
import sys
import time
import warnings
from enum import Enum
from threading import Lock
from types import FrameType
from typing import Dict, Optional

import sentry_sdk
import werkzeug.exceptions
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask import Flask
from flask_apispec import FlaskApiSpec
from flask_cors import CORS
from flask_restful import Api
from geolite2 import geolite2
from sentry_sdk.integrations.flask import FlaskIntegration

from restapi import config
from restapi.config import (
    ABS_RESTAPI_PATH,
    FORCE_PRODUCTION_TESTS,
    PRODUCTION,
    SENTRY_URL,
    TESTING,
    get_backend_url,
    get_frontend_url,
    get_project_configuration,
)
from restapi.connectors import Connector
from restapi.customizer import BaseCustomizer
from restapi.env import Env
from restapi.rest.loader import EndpointsLoader
from restapi.rest.response import (
    ExtendedJSONEncoder,
    handle_marshmallow_errors,
    handle_response,
)
from restapi.services.cache import Cache
from restapi.utilities import print_and_exit
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

lock = Lock()


class ServerModes(int, Enum):
    NORMAL = 0
    INIT = 1
    DESTROY = 2
    WORKER = 3


# def inspect_request():
#     log.critical(request.headers)


def teardown_handler(signal: int, frame: FrameType) -> None:  # pragma: no cover

    with lock:

        Connector.disconnect_all()

    # This is needed to let connectors to complete the disconnection and prevent
    # errors like this on rabbitMQ:
    # closing AMQP connection <0.2684.0> ([...], vhost: '/', user: [...]):
    # client unexpectedly closed TCP connection
    time.sleep(1)
    print("Disconnection completed")
    sys.exit(0)


def create_app(
    name: str = __name__,
    mode: ServerModes = ServerModes.NORMAL,
    options: Optional[Dict[str, bool]] = None,
) -> Flask:
    """Create the server istance for Flask application"""

    if PRODUCTION and TESTING and not FORCE_PRODUCTION_TESTS:  # pragma: no cover
        print_and_exit("Unable to execute tests in production")

    # TERM is not catched by Flask
    # https://github.com/docker/compose/issues/4199#issuecomment-426109482
    # signal.signal(signal.SIGTERM, teardown_handler)
    # SIGINT is registered as STOPSIGNAL in Dockerfile
    signal.signal(signal.SIGINT, teardown_handler)

    # Flask app instance
    # template_folder = template dir for output in HTML
    microservice = Flask(
        name, template_folder=str(ABS_RESTAPI_PATH.joinpath("templates"))
    )

    # CORS
    if not PRODUCTION:

        if TESTING:
            cors_origin = "*"
        else:  # pragma: no cover
            cors_origin = get_frontend_url()
            # Beware, this only works because get_frontend_url never append a port
            cors_origin += ":*"

        CORS(
            microservice,
            allow_headers=[
                "Content-Type",
                "Authorization",
                "X-Requested-With",
                "x-upload-content-length",
                "x-upload-content-type",
                "content-range",
            ],
            supports_credentials=["true"],
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            resources={r"*": {"origins": cors_origin}},
        )

        log.debug("CORS Enabled")

    # Flask configuration from config file
    microservice.config.from_object(config)
    microservice.json_encoder = ExtendedJSONEncoder

    # Used to force flask to avoid json sorting and ensure that
    # the output to reflect the order of field in the Marshmallow schema
    microservice.config["JSON_SORT_KEYS"] = False

    log.debug("Flask app configured")

    if PRODUCTION:
        log.info("Production server mode is ON")

    endpoints_loader = EndpointsLoader()
    mem.configuration = endpoints_loader.load_configuration()

    mem.initializer = Meta.get_class("initialization", "Initializer")
    if not mem.initializer:  # pragma: no cover
        print_and_exit("Invalid Initializer class")

    customizer = Meta.get_class("customization", "Customizer")
    if not customizer:  # pragma: no cover
        print_and_exit("Invalid Customizer class")
    mem.customizer = customizer()

    if not isinstance(mem.customizer, BaseCustomizer):  # pragma: no cover
        print_and_exit("Invalid Customizer class, it should inherit BaseCustomizer")

    Connector.init_app(app=microservice, worker_mode=(mode == ServerModes.WORKER))

    # Initialize reading of all files
    mem.geo_reader = geolite2.reader()
    # when to close??
    # geolite2.close()

    if mode == ServerModes.INIT:
        Connector.project_init(options=options)

    if mode == ServerModes.DESTROY:
        Connector.project_clean()

    # Restful plugin with endpoint mapping (skipped in INIT|DESTROY|WORKER modes)
    if mode == ServerModes.NORMAL:

        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        # ignore warning messages from apispec
        warnings.filterwarnings(
            "ignore", message="Multiple schemas resolved to the name "
        )
        warnings.simplefilter("always", DeprecationWarning)

        mem.cache = Cache.get_instance(microservice)

        endpoints_loader.load_endpoints()
        mem.authenticated_endpoints = endpoints_loader.authenticated_endpoints
        mem.private_endpoints = endpoints_loader.private_endpoints

        # Triggering automatic mapping of REST endpoints
        rest_api = Api(catch_all_404s=True)

        for endpoint in endpoints_loader.endpoints:
            # Create the restful resource with it;
            # this method is from RESTful plugin
            rest_api.add_resource(endpoint.cls, *endpoint.uris)

        # HERE all endpoints will be registered by using FlaskRestful
        rest_api.init_app(microservice)

        # APISpec configuration
        api_url = get_backend_url()
        scheme, host = api_url.rstrip("/").split("://")

        spec = APISpec(
            title=get_project_configuration(
                "project.title", default="Your application name"
            ),
            version=get_project_configuration("project.version", default="0.0.1"),
            openapi_version="2.0",
            # OpenApi 3 not working with FlaskApiSpec
            # -> Duplicate parameter with name body and location body
            # https://github.com/jmcarp/flask-apispec/issues/170
            # Find other warning like this by searching:
            # **FASTAPI**
            # openapi_version="3.0.2",
            plugins=[MarshmallowPlugin()],
            host=host,
            schemes=[scheme],
            tags=endpoints_loader.tags,
        )
        # OpenAPI 3 changed the definition of the security level.
        # Some changes needed here?

        if Env.get_bool("AUTH_ENABLE"):
            api_key_scheme = {"type": "apiKey", "in": "header", "name": "Authorization"}
            spec.components.security_scheme("Bearer", api_key_scheme)

        microservice.config.update(
            {
                "APISPEC_SPEC": spec,
                # 'APISPEC_SWAGGER_URL': '/api/swagger',
                "APISPEC_SWAGGER_URL": None,
                # 'APISPEC_SWAGGER_UI_URL': '/api/swagger-ui',
                # Disable Swagger-UI
                "APISPEC_SWAGGER_UI_URL": None,
            }
        )

        mem.docs = FlaskApiSpec(microservice)

        # Clean app routes
        ignore_verbs = {"HEAD", "OPTIONS"}

        for rule in microservice.url_map.iter_rules():

            view_function = microservice.view_functions[rule.endpoint]
            if not hasattr(view_function, "view_class"):
                continue

            newmethods = ignore_verbs.copy()
            rulename = str(rule)

            if rule.methods:
                for verb in rule.methods - ignore_verbs:
                    method = verb.lower()
                    if method in endpoints_loader.uri2methods[rulename]:
                        # remove from flask mapping
                        # to allow 405 response
                        newmethods.add(verb)

            rule.methods = newmethods

        # Register swagger. Note: after method mapping cleaning
        with microservice.app_context():
            for endpoint in endpoints_loader.endpoints:
                try:
                    mem.docs.register(endpoint.cls)
                except TypeError as e:  # pragma: no cover
                    print(e)
                    log.error("Cannot register {}: {}", endpoint.cls.__name__, e)

    # marshmallow errors handler
    microservice.register_error_handler(422, handle_marshmallow_errors)

    # microservice.before_request(inspect_request)
    # Logging responses
    microservice.after_request(handle_response)

    if SENTRY_URL is not None:  # pragma: no cover

        if PRODUCTION:
            sentry_sdk.init(
                dsn=SENTRY_URL,
                # already catched by handle_marshmallow_errors
                ignore_errors=[werkzeug.exceptions.UnprocessableEntity],
                integrations=[FlaskIntegration()],
            )
            log.info("Enabled Sentry {}", SENTRY_URL)
        else:
            # Could be enabled in print mode
            # sentry_sdk.init(transport=print)
            log.info("Skipping Sentry, only enabled in PRODUCTION mode")

    log.info("Boot completed")

    return microservice
