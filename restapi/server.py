"""
The Main server factory.
We create all the internal flask components here.
"""
import logging
import os
import warnings
from enum import Enum

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
    get_project_configuration,
)
from restapi.customizer import BaseCustomizer
from restapi.rest.loader import EndpointsLoader
from restapi.rest.response import handle_marshmallow_errors, log_response
from restapi.services.detect import detector
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta


class ServerModes(int, Enum):
    NORMAL = 0
    INIT = 1
    DESTROY = 2
    WORKER = 3


def create_app(name=__name__, mode=ServerModes.NORMAL):
    """ Create the server istance for Flask application """

    if PRODUCTION and TESTING and not FORCE_PRODUCTION_TESTS:  # pragma: no cover
        log.exit("Unable to execute tests in production")

    # Flask app instance
    # template_folder = template dir for output in HTML
    microservice = Flask(
        name, template_folder=os.path.join(ABS_RESTAPI_PATH, "templates")
    )

    # CORS
    if not PRODUCTION:
        cors = CORS(
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
        )

        cors.init_app(microservice)
        log.verbose("FLASKING! Injected CORS")

    # Flask configuration from config file
    microservice.config.from_object(config)
    log.debug("Flask app configured")

    if PRODUCTION:
        log.info("Production server mode is ON")

    endpoints_loader = EndpointsLoader()
    mem.configuration = endpoints_loader.load_configuration()

    mem.initializer = Meta.get_class("initialization", "Initializer")
    if not mem.initializer:
        log.exit("Invalid Initializer class")

    mem.customizer = Meta.get_instance("customization", "Customizer")
    if not mem.customizer:
        log.exit("Invalid Customizer class")

    if not isinstance(mem.customizer, BaseCustomizer):
        log.exit("Invalid Customizer class, it should inherit BaseCustomizer")

    # Find services and try to connect to the ones available
    detector.init_services(
        app=microservice,
        project_init=(mode == ServerModes.INIT),
        project_clean=(mode == ServerModes.DESTROY),
        worker_mode=(mode == ServerModes.WORKER),
    )

    # Initialize reading of all files
    mem.geo_reader = geolite2.reader()
    # when to close??
    # geolite2.close()

    # Restful plugin with endpoint mapping (skipped in INIT|DESTROY|WORKER modes)
    if mode == ServerModes.NORMAL:

        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        # ignore warning messages from apispec
        # warnings.filterwarnings(
        #     "ignore", message="Multiple schemas resolved to the name "
        # )

        endpoints_loader.load_endpoints()
        mem.authenticated_endpoints = endpoints_loader.authenticated_endpoints
        mem.private_endpoints = endpoints_loader.private_endpoints

        # Triggering automatic mapping of REST endpoints
        rest_api = Api(catch_all_404s=True)

        for endpoint in endpoints_loader.endpoints:
            # Create the restful resource with it;
            # this method is from RESTful plugin
            rest_api.add_resource(endpoint.cls, *endpoint.uris)

            log.verbose("Map '{}' to {}", endpoint.cls.__name__, endpoint.uris)

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

            endpoint = microservice.view_functions[rule.endpoint]
            if not hasattr(endpoint, "view_class"):
                continue

            newmethods = ignore_verbs.copy()
            rulename = str(rule)

            for verb in rule.methods - ignore_verbs:
                method = verb.lower()
                if method in endpoints_loader.uri2methods[rulename]:
                    # remove from flask mapping
                    # to allow 405 response
                    newmethods.add(verb)
                else:
                    log.verbose("Removed method {}.{} from mapping", rulename, verb)

            rule.methods = newmethods

        # Register swagger. Note: after method mapping cleaning
        with microservice.app_context():
            for endpoint in endpoints_loader.endpoints:
                try:
                    mem.docs.register(endpoint.cls)
                except TypeError as e:
                    print(e)
                    log.error("Cannot register {}: {}", endpoint.cls.__name__, e)

    # marshmallow errors handler
    microservice.register_error_handler(422, handle_marshmallow_errors)

    # Logging responses
    microservice.after_request(log_response)

    if SENTRY_URL is not None:  # pragma: no cover

        if PRODUCTION:
            sentry_sdk.init(
                dsn=SENTRY_URL,
                # already catched by handle_marshmallow_errors
                ignore_errors=(werkzeug.exceptions.UnprocessableEntity,),
                integrations=[FlaskIntegration()],
            )
            log.info("Enabled Sentry {}", SENTRY_URL)
        else:
            # Could be enabled in print mode
            # sentry_sdk.init(transport=print)
            log.info("Skipping Sentry, only enabled in PRODUCTION mode")

    # and the flask App is ready now:
    log.info("Boot completed")

    # return our flask app
    return microservice
