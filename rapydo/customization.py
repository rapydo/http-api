# -*- coding: utf-8 -*-

"""
Customization based on configuration 'blueprint' files
"""

import os
import re
import glob
from rapydo.utils import \
    PROJECT_CONF_FILENAME, CONF_PATH, DEFAULT_FILENAME, UTILS_PKGNAME
from rapydo.utils import helpers
from rapydo.confs import (
    BACKEND_PACKAGE, CUSTOM_PACKAGE,  # CORE_CONFIG_PATH,
    API_URL, BASE_URLS
)
from rapydo.utils.meta import Meta
from rapydo.utils.myyaml import YAML_EXT, load_yaml_file
from rapydo.attributes import EndpointElements, ExtraAttributes
from rapydo.swagger import BeSwagger

from rapydo.utils.logs import get_logger
log = get_logger(__name__)


########################
# Customization on the table
########################

class Customizer(object):
    """
    Customize your BACKEND:
    Read all of available configurations and definitions.
    """

    def __init__(self, testing=False, production=False, init=False):

        # Input
        self._testing = testing
        self._production = production
        self._initiliazing = init

        # Some initialization
        self._endpoints = []
        self._definitions = {}
        self._configurations = {}
        self._query_params = {}
        self._schemas_map = {}
        self._meta = Meta()

        # Do things
        self.do_config()

        if not self._initiliazing:
            self.do_schema()
            self.find_endpoints()
            self.do_swagger()

    def do_config(self):
        ##################
        # Reading configuration

        # Read the custom configuration from the active blueprint file
        custom_config = load_yaml_file(
            PROJECT_CONF_FILENAME,
            # path=CUSTOM_CONFIG_PATH
            path=helpers.current_dir(CUSTOM_PACKAGE, CONF_PATH)
        )
        # custom_config[BLUEPRINT_KEY] = blueprint

        # Read default configuration
        defaults = load_yaml_file(
            DEFAULT_FILENAME,
            # path=CUSTOM_CONFIG_PATH
            path=helpers.script_abspath(__file__, UTILS_PKGNAME)
        )
        if len(defaults) < 0:
            raise ValueError("Missing defaults for server configuration!")

        # Mix default and custom configuration
        # We go deep into two levels down of dictionaries
        for key, elements in defaults.items():
            if key not in custom_config:
                custom_config[key] = {}
            for label, element in elements.items():
                if label not in custom_config[key]:
                    custom_config[key][label] = element

        # Save in memory all of the current configuration
        self._configurations = custom_config

    def do_schema(self):
        """ Schemas exposing, if requested """

        name = '%s.%s.%s' % (BACKEND_PACKAGE, 'rest', 'schema')
        module = self._meta.get_module_from_string(
            name,
            exit_if_not_found=True
        )
        schema_class = getattr(module, 'RecoverSchema')

        self._schema_endpoint = EndpointElements(
            cls=schema_class,
            exists=True,
            custom={
                'methods': {
                    'get': ExtraAttributes(auth=None),
                    # WHY DOES POST REQUEST AUTHENTICATION
                    # 'post': ExtraAttributes(auth=None)
                }
            },
            methods={}
        )

        # TODO: find a way to map authentication
        # as in the original endpoint for the schema 'get' method

        # TODO: find a way to publish on swagger the schema
        # if endpoint is enabled to publish and the developer asks for it

    def find_endpoints(self):

        ##################
        # Walk swagger directories looking for endpoints

        # FIXME: how to do this?
        # from rapydo.utils import helpers
        # custom_dir = helpers.current_dir(CUSTOM_PACKAGE)
        # base_dir = helpers.script_abspath(__file__)

        base_swagger_confdir = helpers.script_abspath(__file__)
        custom_swagger_confdir = helpers.current_dir(CUSTOM_PACKAGE)

        # for base_dir in [BACKEND_PACKAGE, CUSTOM_PACKAGE]:
        for base_dir in [base_swagger_confdir, custom_swagger_confdir]:

            swagger_dir = os.path.join(base_dir, 'swagger')
            log.verbose("Swagger dir: %s" % swagger_dir)

            for ep in os.listdir(swagger_dir):

                swagger_endpoint_dir = os.path.join(swagger_dir, ep)

                if os.path.isfile(swagger_endpoint_dir):
                    log.debug(
                        "Expected a swagger conf folder, found a file (%s)"
                        % (swagger_endpoint_dir)
                    )
                    continue

                # isbase = base_dir == BACKEND_PACKAGE
                isbase = base_dir.startswith('/usr/local')
                base_module = helpers.last_dir(base_dir)
                if isbase:
                    apiclass_module = '%s.%s' % (base_module, 'resources')
                else:
                    apiclass_module = '%s.%s' % (base_module, 'apis')

                current = self.lookup(
                    ep, apiclass_module, swagger_endpoint_dir, isbase)
                if current is not None and current.exists:
                    # Add endpoint to REST mapping
                    self._endpoints.append(current)

    def do_swagger(self):

        # SWAGGER read endpoints definition
        swag = BeSwagger(self._endpoints, self)
        swag_dict = swag.swaggerish()

        # TODO: update internal endpoints from swagger
        self._endpoints = swag._endpoints[:]

        # SWAGGER validation
        if not swag.validation(swag_dict):
            log.critical_exit("Current swagger definition is invalid")

        self._definitions = swag_dict

    def read_frameworks(self):

        file = os.path.join("config", "frameworks.yaml")
        self._frameworks = load_yaml_file(file)

    def lookup(self, endpoint, apiclass_module, swagger_endpoint_dir, isbase):

        log.verbose("Found endpoint dir: '%s'" % endpoint)

        if os.path.exists(os.path.join(swagger_endpoint_dir, 'SKIP')):
            log.info("Skipping: %s" % endpoint)
            return None

        # Find yaml files
        conf = None
        yaml_files = {}
        yaml_listing = os.path.join(swagger_endpoint_dir, "*.%s" % YAML_EXT)

        for file in glob.glob(yaml_listing):
            if file.endswith('specs.%s' % YAML_EXT):
                # load configuration and find file and class
                conf = load_yaml_file(file)
            else:
                # add file to be loaded from swagger extension
                p = re.compile(r'\/([^\.\/]+)\.' + YAML_EXT + '$')
                match = p.search(file)
                method = match.groups()[0]
                yaml_files[method] = file

        if len(yaml_files) < 1:
            raise Exception("%s: no methods defined in any YAML" % endpoint)
        if conf is None or 'class' not in conf:
            raise ValueError("No 'class' defined for '%s'" % endpoint)

        current = self.load_endpoint(endpoint, apiclass_module, conf, isbase)
        current.methods = yaml_files
        return current

    # def read_complex_config(self, configfile):
    #     """ A more complex configuration is available in JSON format """
    #     content = {}
    #     with open(configfile) as fp:
    #         content = json.load(fp)
    #     return content

    def load_endpoint(self, default_uri, apiclass_module, conf, isbase):

        endpoint = EndpointElements(custom={})

        #####################
        # Load the endpoint class defined in the YAML file
        file_name = conf.pop('file', default_uri)
        class_name = conf.pop('class')
        name = '%s.%s' % (apiclass_module, file_name)
        module = self._meta.get_module_from_string(name)

        if module is None:
            debugger = log.warning
            if self._production:
                debugger = log.critical_exit
            debugger("Could not find module %s (in %s)" % (name, file_name))
            return endpoint

        #####################
        # Check for dependecies and skip if missing
        for dependency in conf.pop('depends_on', []):
            # TOFIX: uhm? Should verify the env variable {SERVICE}_ENABLE?
            if not getattr(module, dependency, False):
                log.debug("Skip '%s': unmet %s" % (default_uri, dependency))
                return endpoint

        endpoint.cls = self._meta.get_class_from_string(class_name, module)
        if endpoint.cls is None:
            log.critical("Could not extract python class '%s'" % class_name)
            return endpoint
        else:
            endpoint.exists = True

        # Is this a base or a custom class?
        endpoint.isbase = isbase

        # DEPRECATED
        # endpoint.instance = endpoint.cls()

        # Global tags
        # to be applied to all methods
        endpoint.tags = conf.pop('labels', [])

        # base URI
        base = conf.pop('baseuri', API_URL)
        if base not in BASE_URLS:
            log.warning("Invalid base %s" % base)
            base = API_URL
        base = base.strip('/')

        #####################
        # MAPPING
        schema = conf.pop('schema', {})
        mappings = conf.pop('mapping', [])
        if len(mappings) < 1:
            raise KeyError("Missing 'mapping' section")

        endpoint.uris = {}  # attrs python lib bug?
        endpoint.custom['schema'] = {
            'expose': schema.get('expose', False),
            'publish': {}
        }
        for label, uri in mappings.items():

            # BUILD URI
            total_uri = '/%s%s' % (base, uri)
            endpoint.uris[label] = total_uri

            # If SCHEMA requested create
            if endpoint.custom['schema']['expose']:

                schema_uri = '%s%s%s' % (API_URL, '/schemas', uri)

                p = hex(id(endpoint.cls))
                self._schema_endpoint.uris[label + p] = schema_uri

                endpoint.custom['schema']['publish'][label] = \
                    schema.get('publish', False)

                self._schemas_map[schema_uri] = total_uri

        # Description for path parameters
        endpoint.ids = conf.pop('ids', {})

        # Check if something strange is still in configuration
        if len(conf) > 0:
            raise KeyError("Unwanted keys: %s" % list(conf.keys()))

        return endpoint
