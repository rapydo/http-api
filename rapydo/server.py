# -*- coding: utf-8 -*-

"""
The Main server factory.
We create all the internal flask components here.
"""

import better_exceptions as be
import rapydo.confs as config
import warnings
from flask import Flask as OriginalFlask, request
from flask_injector import FlaskInjector
from rapydo.protocols.cors import cors
from rapydo.rest.response import InternalResponse
from werkzeug.contrib.fixers import ProxyFix
from rapydo.rest.response import ResponseMaker
from rapydo.customization import Customizer
from rapydo.confs import PRODUCTION
from rapydo.utils.globals import mem
from rapydo.protocols.restful import Api, EndpointsFarmer, create_endpoints
from rapydo.services.detect import detector

from rapydo.utils.logs import \
    get_logger, \
    handle_log_output, MAX_CHAR_LEN, set_global_log_level


#############################
# LOGS
log = get_logger(__name__)

# This is the first file to be imported in the project
# We need to enable many things on a global level for logs
set_global_log_level(package=__package__)


#############################
class Flask(OriginalFlask):

    def make_response(self, rv, response_log_max_len=MAX_CHAR_LEN):
        """
        Hack original flask response generator to read our internal response
        and build what is needed:
        the tuple (data, status, headers) to be eaten by make_response()
        """

        try:
            # Limit the output, sometimes it's too big
            out = str(rv)
            if len(out) > response_log_max_len:
                out = out[:response_log_max_len] + ' ...'
            # log.very_verbose("Custom response built: %s" % out)
        except BaseException:
            log.debug("Response: [UNREADABLE OBJ]")
        responder = ResponseMaker(rv)

        # Avoid duplicating the response generation
        # or the make_response replica.
        # This happens with Flask exceptions
        if responder.already_converted():
            log.very_verbose("Response was already converted")
            # # Note: this response could be a class ResponseElements
            # return rv

            # The responder instead would have already found the right element
            return responder.get_original_response()

        # Note: jsonify gets done when calling the make_response,
        # so make sure that the data is written in  the right format!
        response = responder.generate_response()
        return super().make_response(response)


########################
# Flask App factory    #
########################
def create_app(name=__name__,
               init_mode=False, destroy_mode=False,
               worker_mode=False, testing_mode=False,
               skip_endpoint_mapping=False,
               **kwargs):
    """ Create the server istance for Flask application """

    #############################
    # Initialize reading of all files
    mem.customizer = Customizer(testing_mode, PRODUCTION, init_mode)
    # TOFIX: try to remove mem. from everywhere...

    #################################################
    # Flask app instance
    #################################################
    microservice = Flask(name, **kwargs)

    ##############################
    # Add commands to 'flask' binary
    if init_mode:
        microservice.config['INIT_MODE'] = init_mode
        skip_endpoint_mapping = True

        @microservice.cli.command()
        def init():
            """Initialize the current app"""
            log.warning("Initialization completed")
    elif destroy_mode:
        microservice.config['DESTROY_MODE'] = destroy_mode
        skip_endpoint_mapping = True

        @microservice.cli.command()
        def destroy():
            """Destory current data from the app"""
            log.warning("Data removal completed")
    elif testing_mode:
        microservice.config['TESTING'] = testing_mode
    elif worker_mode:
        skip_endpoint_mapping = True

    ##############################
    # Fix proxy wsgi for production calls
    microservice.wsgi_app = ProxyFix(microservice.wsgi_app)

    ##############################
    # Cors
    cors.init_app(microservice)
    log.verbose("FLASKING! Injected CORS")

    ##############################
    # Enabling our internal Flask customized response
    microservice.response_class = InternalResponse

    ##############################
    # Flask configuration from config file
    microservice.config.from_object(config)
    log.debug("Flask app configured")

    ##############################
    if PRODUCTION:

        log.info("Production server mode is ON")

        # TOFIX: random secrety key in production
        # # Check and use a random file a secret key.
        # install_secret_key(microservice)

        # # To enable exceptions printing inside uWSGI
        # # http://stackoverflow.com/a/17839750/2114395
        # from werkzeug.debug import DebuggedApplication
        # app.wsgi_app = DebuggedApplication(app.wsgi_app, True)

    ##############################
    # Find services and try to connect to the ones available
    extensions = detector.init_services(
        app=microservice, worker_mode=worker_mode,
        project_init=init_mode, project_clean=destroy_mode
    )

    if worker_mode:
        microservice.extensions = extensions

    ##############################
    # Restful plugin
    if not skip_endpoint_mapping:
        # Triggering automatic mapping of REST endpoints
        current_endpoints = create_endpoints(EndpointsFarmer(Api))
        # Restful init of the app
        current_endpoints.rest_api.init_app(microservice)

        ##############################
        # Injection!
        # Enabling "configuration modules" for services to be injected
        # IMPORTANT: Injector must be initialized AFTER mapping endpoints

        modules = detector.load_injector_modules()

        # AVOID warnings from Flask Injector
        warnings.filterwarnings("ignore")
        FlaskInjector(app=microservice, modules=modules)

        # Catch warnings from Flask Injector
        # try:
        #     FlaskInjector(app=microservice, modules=modules)
        # except RuntimeWarning:
        #     pass

    ##############################
    # Clean app routes
    ignore_verbs = {"HEAD", "OPTIONS"}

    for rule in microservice.url_map.iter_rules():

        rulename = str(rule)
        # Skip rules that are only exposing schemas
        if '/schemas/' in rulename:
            continue

        endpoint = microservice.view_functions[rule.endpoint]
        if not hasattr(endpoint, 'view_class'):
            continue
        newmethods = ignore_verbs.copy()

        for verb in rule.methods - ignore_verbs:
            method = verb.lower()
            if method in mem.customizer._original_paths[rulename]:
                # remove from flask mapping
                # to allow 405 response
                newmethods.add(verb)
            else:
                log.verbose("Removed method %s.%s from mapping" %
                            (rulename, verb))

        rule.methods = newmethods

        # TOFIX: SOLVE CELERY INJECTION
        # # Set global objects for celery workers
        # if worker_mode:
        #     mem.services = internal_services

    ##############################
    # Logging responses
    @microservice.after_request
    def log_response(response):

        data = handle_log_output(request.data)

        # Limit the parameters string size, sometimes it's too big
        for k in data:
            try:
                if not isinstance(data[k], str):
                    continue
                if len(data[k]) > MAX_CHAR_LEN:
                    data[k] = data[k][:MAX_CHAR_LEN] + "..."
            except IndexError:
                pass

        log.info("{} {} {} {}".format(
                 request.method, request.url, data, response))
        return response

    ##############################
    # and the flask App is ready now:
    log.info("Boot completed")
    # activate better loggings
    be
    # return our flask app
    return microservice
