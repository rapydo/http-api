# -*- coding: utf-8 -*-

"""
The Main server factory.
We create all the internal flask components here.
"""
import os
import warnings
from urllib import parse as urllib_parse
from flask import Flask as OriginalFlask, request
from flask_injector import FlaskInjector
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from geolite2 import geolite2
from restapi import confs as config
from restapi.confs import ABS_RESTAPI_PATH
from restapi.rest.response import InternalResponse
from restapi.rest.response import ResponseMaker
from restapi.customization import Customizer
from restapi.confs import PRODUCTION
from restapi.confs import SENTRY_URL
from restapi.protocols.restful import Api
from restapi.services.detect import detector
from restapi.services.mail import send_mail_is_active, test_smtp_client
from restapi.utilities.globals import mem
from restapi.utilities.logs import log, handle_log_output, MAX_CHAR_LEN

#############################

# from restapi.utilities.logs import set_global_log_level,
# This is the first file to be imported in the project
# We need to enable many things on a global level for logs
# set_global_log_level(package=__package__)


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
        except BaseException:
            log.debug("Response: [UNREADABLE OBJ]")
        responder = ResponseMaker(rv)

        # Avoid duplicating the response generation
        # or the make_response replica.
        # This happens with Flask exceptions
        if responder.already_converted():
            # # Note: this response could be a class ResponseElements
            # return rv

            # The responder instead would have already found the right element
            return responder.get_original_response()

        # Note: jsonify gets done when calling the make_response,
        # so make sure that the data is written in the right format!
        r = responder.generate_response()
        response = super().make_response(r)
        # TOFIX: avoid duplicated Content-type
        # the jsonify in respose.py#force_type force the content-type
        # to be application/json. If content-type is already specified in headers
        # the header will have a duplicated Content-type. We should fix by avoding
        # jsonfy for more specific mimetypes
        # For now I will simply remove the duplicates
        content_type = None
        for idx, val in enumerate(response.headers):
            if val[0] != 'Content-Type':
                continue
            if content_type is None:
                content_type = idx
                continue
            log.warning(
                "Duplicated Content-Type, removing {} and keeping {}",
                response.headers[content_type][1],
                val[1],
            )
            response.headers.pop(content_type)
            break
        return response


########################
# Flask App factory    #
########################
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

    if PRODUCTION and testing_mode:
        log.exit("Unable to execute tests in production")

    # Initialize reading of all files
    mem.customizer = Customizer(testing_mode, init_mode)
    mem.geo_reader = geolite2.reader()
    # when to close??
    # geolite2.close()

    # Add template dir for output in HTML
    kwargs['template_folder'] = os.path.join(ABS_RESTAPI_PATH, 'templates')

    #################################################
    # Flask app instance
    #################################################

    microservice = Flask(name, **kwargs)

    # Add commands to 'flask' binary
    if init_mode:
        microservice.config['INIT_MODE'] = init_mode
        skip_endpoint_mapping = True
    elif destroy_mode:
        microservice.config['DESTROY_MODE'] = destroy_mode
        skip_endpoint_mapping = True
    elif testing_mode:
        microservice.config['TESTING'] = testing_mode
        init_mode = True
    elif worker_mode:
        skip_endpoint_mapping = True

    ##############################
    # Fix proxy wsgi for production calls
    microservice.wsgi_app = ProxyFix(microservice.wsgi_app)

    ##############################
    # CORS
    if not PRODUCTION:
        cors = CORS(
            allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'x-upload-content-length', 'x-upload-content-type', 'content-range'],
            supports_credentials=['true'],
            methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        )

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

    ##############################
    # Find services and try to connect to the ones available
    extensions = detector.init_services(
        app=microservice,
        worker_mode=worker_mode,
        project_init=init_mode,
        project_clean=destroy_mode,
    )

    if worker_mode:
        microservice.extensions = extensions

    ##############################
    # Restful plugin
    if not skip_endpoint_mapping:
        # Triggering automatic mapping of REST endpoints
        rest_api = Api(catch_all_404s=True)

        # Basic configuration (simple): from example class
        if len(mem.customizer._endpoints) < 1:
            log.error("No endpoints found!")

            raise AttributeError("Follow the docs and define your endpoints")

        for resource in mem.customizer._endpoints:
            urls = [uri for _, uri in resource.uris.items()]

            # Create the restful resource with it;
            # this method is from RESTful plugin
            rest_api.add_resource(resource.cls, *urls)
            log.verbose("Map '{}' to {}", resource.cls.__name__, urls)

        # Enable all schema endpoints to be mapped with this extra step
        if len(mem.customizer._schema_endpoint.uris) > 0:
            log.debug("Found one or more schema to expose")
            urls = [uri for _, uri in mem.customizer._schema_endpoint.uris.items()]
            rest_api.add_resource(mem.customizer._schema_endpoint.cls, *urls)

        # HERE all endpoints will be registered by using FlaskRestful
        rest_api.init_app(microservice)

        ##############################
        # Injection!
        # Enabling "configuration modules" for services to be injected
        # IMPORTANT: Injector must be initialized AFTER mapping endpoints

        modules = detector.load_injector_modules()

        # AVOID warnings from Flask Injector
        warnings.filterwarnings("ignore")

        FlaskInjector(app=microservice, modules=modules)

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
                log.verbose("Removed method {}.{} from mapping", rulename, verb)

        rule.methods = newmethods

    ##############################
    # Logging responses
    @microservice.after_request
    def log_response(response):

        ###############################
        # NOTE: if it is an upload,
        # I must NOT consume request.data or request.json,
        # otherwise the content gets lost
        do_not_log_types = ['application/octet-stream', 'multipart/form-data']

        if request.mimetype in do_not_log_types:
            data = 'STREAM_UPLOAD'
        else:
            try:
                data = handle_log_output(request.data)
                # Limit the parameters string size, sometimes it's too big
                for k in data:
                    try:
                        if isinstance(data[k], dict):
                            for kk in data[k]:
                                v = str(data[k][kk])
                                if len(v) > MAX_CHAR_LEN:
                                    v = v[:MAX_CHAR_LEN] + "..."
                                data[k][kk] = v
                            continue

                        if not isinstance(data[k], str):
                            data[k] = str(data[k])

                        if len(data[k]) > MAX_CHAR_LEN:
                            data[k] = data[k][:MAX_CHAR_LEN] + "..."
                    except IndexError:
                        pass
            except Exception:
                data = 'OTHER_UPLOAD'

        # Obfuscating query parameters
        url = urllib_parse.urlparse(request.url)
        try:
            params = urllib_parse.unquote(
                urllib_parse.urlencode(handle_log_output(url.query))
            )
            url = url._replace(query=params)
        except TypeError:
            log.error("Unable to url encode the following parameters:")
            print(url.query)

        url = urllib_parse.urlunparse(url)
        log.info("{} {} {} {}", request.method, url, data, response)

        return response

    if send_mail_is_active():
        if not test_smtp_client():
            log.critical("Bad SMTP configuration, unable to create a client")
        else:
            log.info("SMTP configuration verified")
    ##############################
    # and the flask App is ready now:
    log.info("Boot completed")

    if SENTRY_URL is not None:

        if not PRODUCTION:
            log.info("Skipping Sentry, only enabled in PRODUCTION mode")
        else:
            import sentry_sdk
            from sentry_sdk.integrations.flask import FlaskIntegration

            sentry_sdk.init(dsn=SENTRY_URL, integrations=[FlaskIntegration()])
            log.info("Enabled Sentry {}", SENTRY_URL)

    # return our flask app
    return microservice
