"""
The Main server factory.
We create all the internal flask components here.
"""
import logging
import os

import sentry_sdk
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask import Flask
from flask_apispec import FlaskApiSpec, MethodResource
from flask_cors import CORS
from flask_restful import Api
from geolite2 import geolite2
from sentry_sdk.integrations.flask import FlaskIntegration

from restapi import confs as config
from restapi.confs import (
    ABS_RESTAPI_PATH,
    PRODUCTION,
    SENTRY_URL,
    get_project_configuration,
)
from restapi.customization import Customizer
from restapi.rest.response import handle_marshmallow_errors, log_response
from restapi.services.detect import detector
from restapi.services.mail import send_mail_is_active, test_smtp_client
from restapi.utilities.globals import mem
from restapi.utilities.logs import log


def create_app(
    name=__name__,
    init_mode=False,
    destroy_mode=False,
    worker_mode=False,
    testing_mode=False,
    skip_endpoint_mapping=False,
    **kwargs,
):
    """ Create the server istance for Flask application """

    if PRODUCTION and testing_mode and not config.FORCE_PRODUCTION_TESTS:
        log.exit("Unable to execute tests in production")
    if testing_mode and not config.TESTING:  # pragma: no cover
        # Deprecated since 0.7.3
        log.exit(
            "Deprecated use of testing_mode, please export env variable APP_MODE=test"
        )

    # Add template dir for output in HTML
    kwargs["template_folder"] = os.path.join(ABS_RESTAPI_PATH, "templates")

    # Flask app instance
    microservice = Flask(name, **kwargs)

    # Add commands to 'flask' binary
    if init_mode:
        # microservice.config['INIT_MODE'] = init_mode
        skip_endpoint_mapping = True
        test_smtp = False
    elif destroy_mode:
        # microservice.config['DESTROY_MODE'] = destroy_mode
        skip_endpoint_mapping = True
        test_smtp = False
    elif testing_mode:
        # microservice.config['TESTING'] = testing_mode
        init_mode = True
        test_smtp = True
    elif worker_mode:
        skip_endpoint_mapping = True
        test_smtp = True

    # Fix proxy wsgi for production calls
    # from werkzeug.middleware.proxy_fix import ProxyFix
    # microservice.wsgi_app = ProxyFix(microservice.wsgi_app)

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

    mem.customizer = Customizer()
    mem.configuration = mem.customizer.load_configuration()

    # Find services and try to connect to the ones available
    detector.init_services(
        app=microservice, project_init=init_mode, project_clean=destroy_mode,
    )

    # Initialize reading of all files
    mem.geo_reader = geolite2.reader()
    # when to close??
    # geolite2.close()

    # Restful plugin
    if not skip_endpoint_mapping:

        mem.customizer.find_endpoints()
        mem.customizer.do_swagger()
        # Triggering automatic mapping of REST endpoints
        rest_api = Api(catch_all_404s=True)

        # Basic configuration (simple): from example class
        if len(mem.customizer._endpoints) < 1:
            log.error("No endpoints found!")

            raise AttributeError("Follow the docs and define your endpoints")

        for endpoint in mem.customizer._endpoints:
            # urls = [uri for _, uri in resource.uris.items()]
            urls = list(endpoint.uris.values())

            # Create the restful resource with it;
            # this method is from RESTful plugin
            rest_api.add_resource(endpoint.cls, *urls)

            log.verbose("Map '{}' to {}", endpoint.cls.__name__, urls)

        # HERE all endpoints will be registered by using FlaskRestful
        rest_api.init_app(microservice)

        microservice.config.update(
            {
                "APISPEC_SPEC": APISpec(
                    title=get_project_configuration(
                        "project.title", default="Your application name"
                    ),
                    version=get_project_configuration(
                        "project.version", default="0.0.1"
                    ),
                    openapi_version="2.0",
                    # OpenApi 3 not working with FlaskApiSpec
                    # -> Duplicate parameter with name body and location body
                    # https://github.com/jmcarp/flask-apispec/issues/170
                    # Find other warning like this by searching:
                    # **FASTAPI**
                    # openapi_version="3.0.2",
                    plugins=[MarshmallowPlugin()],
                ),
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

            rulename = str(rule)
            # Skip rules that are only exposing schemas
            if "/schemas/" in rulename:
                continue

            endpoint = microservice.view_functions[rule.endpoint]
            if not hasattr(endpoint, "view_class"):
                continue
            newmethods = ignore_verbs.copy()

            for verb in rule.methods - ignore_verbs:
                method = verb.lower()
                if method in mem.customizer._original_paths[rulename]:
                    # remove from flask mapping
                    # to allow 405 response
                    newmethods.add(verb)
                else:
                    log.verbose("Removed method {}.{} from mapping", rulename, verb)

            rule.methods = newmethods

        # Register swagger. Note: after method mapping cleaning
        with microservice.app_context():
            for endpoint in mem.customizer._endpoints:
                urls = list(endpoint.uris.values())
                try:
                    mem.docs.register(endpoint.cls)
                except TypeError as e:
                    # log.warning("{} on {}", type(e), endpoint.cls)
                    # Enable this warning to start conversion to FlaskFastApi
                    # Find other warning like this by searching:
                    # **FASTAPI**
                    # for m, v in endpoint.custom['params'].items():
                    #     log.critical("{} = {}", m, v)
                    if MethodResource in endpoint.cls.__bases__:
                        log.error("Cannot register {}: {}", endpoint.cls.__name__, e)
                    elif endpoint.iscore:
                        if endpoint.cls.__name__ != "SwaggerSpecifications":
                            log.warning("Core endpoint: {}", endpoint.cls.__name__)
                    else:
                        log.verbose("{} on {}", type(e), endpoint.cls)

    # marshmallow errors handler
    microservice.register_error_handler(422, handle_marshmallow_errors)

    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    # Logging responses
    microservice.after_request(log_response)

    if test_smtp and send_mail_is_active():
        if not test_smtp_client():
            log.critical("Bad SMTP configuration, unable to create a client")
        else:
            log.info("SMTP configuration verified")

    if SENTRY_URL is not None:

        if not PRODUCTION:
            log.info("Skipping Sentry, only enabled in PRODUCTION mode")
        else:

            sentry_sdk.init(dsn=SENTRY_URL, integrations=[FlaskIntegration()])
            log.info("Enabled Sentry {}", SENTRY_URL)

    # and the flask App is ready now:
    log.info("Boot completed")

    # return our flask app
    return microservice
