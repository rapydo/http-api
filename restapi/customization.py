# -*- coding: utf-8 -*-

"""
Customization based on configuration 'blueprint' files
"""

import os
import re
import glob
import copy

from restapi.confs import API_URL, BASE_URLS, ABS_RESTAPI_PATH, CONF_PATH
from restapi.confs import BACKEND_PACKAGE, CUSTOM_PACKAGE
from restapi.services.detect import detector
from restapi.attributes import EndpointElements, ExtraAttributes
from restapi.swagger import BeSwagger
from restapi.utilities.meta import Meta

from restapi.utilities import configuration as conf
from restapi.utilities.configuration import load_yaml_file
from restapi.utilities.logs import get_logger

log = get_logger(__name__)
meta = Meta()

CONF_FOLDERS = detector.load_group(label='project_confs')


########################
# Customization on the table
########################
class Customizer(object):
    """
    Customize your BACKEND:
    Read all of available configurations and definitions.
    """

    def __init__(self, testing=False, init=False):

        # Input
        self._testing = testing

        # Some initialization
        self._endpoints = []
        self._definitions = {}
        self._configurations = {}
        self._query_params = {}
        self._schemas_map = {}

        # Do things
        self.read_configuration()

        if not init:
            self.do_schema()
            self.find_endpoints()
            self.do_swagger()

    def read_configuration(self):
        ##################
        # Reading configuration

        confs_path = os.path.join(os.curdir, CONF_PATH)

        if 'defaults_path' in CONF_FOLDERS:
            defaults_path = CONF_FOLDERS['defaults_path']
        else:
            defaults_path = confs_path

        if 'base_path' in CONF_FOLDERS:
            base_path = CONF_FOLDERS['base_path']
        else:
            base_path = confs_path

        if 'projects_path' in CONF_FOLDERS:
            projects_path = CONF_FOLDERS['projects_path']
        else:
            projects_path = confs_path

        if 'submodules_path' in CONF_FOLDERS:
            submodules_path = CONF_FOLDERS['submodules_path']
        else:
            submodules_path = confs_path

        self._configurations, self._extended_project, self._extended_path = conf.read(
            default_file_path=defaults_path,
            base_project_path=base_path,
            projects_path=projects_path,
            submodules_path=submodules_path,
            from_container=True,
            do_exit=True,
        )

    def do_schema(self):
        """ Schemas exposing, if requested """

        name = '%s.%s.%s' % (BACKEND_PACKAGE, 'rest', 'schema')
        module = Meta.get_module_from_string(
            name, exit_if_not_found=True, exit_on_fail=True
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
            methods={},
        )

        # TODO: find a way to map authentication
        # as in the original endpoint for the schema 'get' method

        # TODO: find a way to publish on swagger the schema
        # if endpoint is enabled to publish and the developer asks for it

    def find_endpoints(self):

        ##################
        # Walk folders looking for endpoints

        endpoints_folders = []
        # base swagger dir (rapydo/http-ap)
        endpoints_folders.append(
            {'path': ABS_RESTAPI_PATH, 'iscore': True}
        )

        # swagger dir from extended project, if any
        if self._extended_project is not None:

            endpoints_folders.append(
                {
                    'path': os.path.join(os.curdir, self._extended_project),
                    'iscore': False
                }
            )

        # custom swagger dir
        endpoints_folders.append(
            {'path': os.path.join(os.curdir, CUSTOM_PACKAGE), 'iscore': False}
        )

        simple_override_check = {}
        already_loaded = {}
        for folder in endpoints_folders:

            base_dir = folder.get('path')
            iscore = folder.get('iscore')
            # get last item of the path
            # normapath is required to strip final / is any
            base_module = os.path.basename(os.path.normpath(base_dir))

            if iscore:
                apis_dir = os.path.join(base_dir, 'resources')
                apiclass_module = '%s.%s' % (base_module, 'resources')
            else:
                apis_dir = os.path.join(base_dir, 'apis')
                apiclass_module = '%s.%s' % (base_module, 'apis')

            # Looking for all file in apis folder
            for epfiles in os.listdir(apis_dir):

                # get module name (es: apis.filename)
                module_file = os.path.splitext(epfiles)[0]
                module_name = "%s.%s" % (apiclass_module, module_file)
                # Convert module name into a module
                try:
                    module = Meta.get_module_from_string(module_name, exit_on_fail=True)
                except BaseException as e:
                    log.exit("Cannot import %s\nError: %s", module_name, e)

                # Extract classes from the module
                classes = meta.get_classes_from_module(module)
                for class_name in classes:
                    ep_class = classes.get(class_name)
                    # Filtering out classes without required data
                    if not hasattr(ep_class, "methods"):
                        continue
                    if ep_class.methods is None:
                        continue

                    if class_name in already_loaded:
                        log.warning(
                            "Skipping import of %s from %s.%s, already loded from %s",
                            class_name,
                            apis_dir,
                            module_file,
                            already_loaded[class_name],
                        )
                        continue
                    already_loaded[class_name] = "%s.%s" % (apis_dir, module_file)
                    log.debug(
                        "Importing %s from %s", class_name, already_loaded[class_name]
                    )
                    if not self._testing:
                        skip = False
                        for var in ep_class.depends_on:
                            pieces = var.strip().split(' ')
                            pieces_num = len(pieces)
                            if pieces_num == 1:
                                dependency = pieces.pop()
                                negate = False
                            elif pieces_num == 2:
                                negate, dependency = pieces
                                negate = negate.lower() == 'not'
                            else:
                                log.exit('Wrong parameter: %s', var)

                            check = detector.get_bool_from_os(dependency)
                            if negate:
                                check = not check

                            # Skip if not meeting the requirements of the dependency
                            if not check:
                                skip = True
                                break

                        if skip:
                            log.debug(
                                "Skip '%s %s': unmet %s",
                                module_name,
                                class_name,
                                dependency
                            )
                            continue

                    # Building endpoint
                    endpoint = EndpointElements(custom={})

                    endpoint.cls = ep_class
                    endpoint.exists = True
                    endpoint.iscore = iscore

                    # Global tags to be applied to all methods
                    endpoint.tags = ep_class.labels

                    # base URI
                    base = ep_class.baseuri
                    if base not in BASE_URLS:
                        log.warning("Invalid base %s", base)
                        base = API_URL
                    base = base.strip('/')
                    endpoint.base_uri = base

                    endpoint.uris = {}  # attrs python lib bug?
                    endpoint.custom['schema'] = {
                        'expose': ep_class.expose_schema,
                        'publish': {},
                    }

                    endpoint.methods = {}

                    mapping_lists = []
                    for m in ep_class.methods:
                        if not hasattr(ep_class, m):
                            log.warning(
                                "%s configuration not found in %s", m, class_name
                            )
                            continue
                        conf = getattr(ep_class, m)
                        kk = conf.keys()
                        mapping_lists.extend(kk)
                        endpoint.methods[m.lower()] = copy.deepcopy(conf)

                    if endpoint.custom['schema']['expose']:
                        for uri in mapping_lists:
                            total_uri = '/%s%s' % (endpoint.base_uri, uri)
                            schema_uri = '%s%s%s' % (API_URL, '/schemas', uri)

                            p = hex(id(endpoint.cls))
                            self._schema_endpoint.uris[uri + p] = schema_uri

                            # endpoint.custom['schema']['publish'][uri] = ep_class.publish
                            self._schemas_map[schema_uri] = total_uri

                    self._endpoints.append(endpoint)

            swagger_dir = os.path.join(base_dir, 'swagger')
            if not iscore and os.path.exists(swagger_dir):
                log.verbose("Swagger dir: %s", swagger_dir)

                for ep in os.listdir(swagger_dir):

                    if ep in simple_override_check:
                        log.warning(
                            "%s already loaded from %s",
                            ep,
                            simple_override_check.get(ep),
                        )
                        continue
                    simple_override_check[ep] = base_dir

                    swagger_endpoint_dir = os.path.join(swagger_dir, ep)

                    if os.path.isfile(swagger_endpoint_dir):
                        log.debug(
                            "Found a file instead of a folder: %s", swagger_endpoint_dir
                        )
                        continue

                    # get last item of the path
                    # normapath is required to strip final / is any
                    base_module = os.path.basename(os.path.normpath(base_dir))

                    if iscore:
                        apiclass_module = '%s.%s' % (base_module, 'resources')
                    else:
                        apiclass_module = '%s.%s' % (base_module, 'apis')

                    log.warning("Deprecated endpoint configuration from yaml: %s", ep)

                    current = self.lookup(
                        ep, apiclass_module, swagger_endpoint_dir, iscore
                    )

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
            log.exit("Current swagger definition is invalid")

        self._definitions = swag_dict

    def lookup(self, endpoint, apiclass_module, swagger_endpoint_dir, iscore):

        log.verbose("Found endpoint dir: '%s'", endpoint)

        if os.path.exists(os.path.join(swagger_endpoint_dir, 'SKIP')):
            log.info("Skipping: %s", endpoint)
            return None

        # Find yaml files
        conf = None
        yaml_files = {}
        yaml_listing = os.path.join(swagger_endpoint_dir, "*.yaml")

        for file in glob.glob(yaml_listing):
            if file.endswith('specs.yaml'):
                # load configuration and find file and class
                conf = load_yaml_file(file)
            else:
                # add file to be loaded from swagger extension
                p = re.compile(r'\/([^\.\/]+)\.yaml$')
                match = p.search(file)
                method = match.groups()[0]
                yaml_files[method] = file

        if len(yaml_files) < 1:
            raise Exception("%s: no methods defined in any YAML" % endpoint)
        if conf is None or 'class' not in conf:
            raise ValueError("No 'class' defined for '%s'" % endpoint)

        current = self.load_endpoint(apiclass_module, conf, iscore)
        current.methods = yaml_files
        return current

    def load_endpoint(self, apiclass_module, conf, iscore):

        endpoint = EndpointElements(custom={})

        # Load the endpoint class defined in the YAML file
        file_name = conf.pop('file')
        class_name = conf.pop('class')
        name = '%s.%s' % (apiclass_module, file_name)
        module = Meta.get_module_from_string(name, exit_on_fail=False)

        # Error if unable to find the module in python
        if module is None:
            log.exit("Could not find module %s (in %s)", name, file_name)

        # Check for dependecies and skip if missing
        for var in conf.pop('depends_on', []):

            negate = ''
            pieces = var.strip().split(' ')
            pieces_num = len(pieces)
            if pieces_num == 1:
                dependency = pieces.pop()
            elif pieces_num == 2:
                negate, dependency = pieces
            else:
                log.exit('Wrong parameter: %s', var)

            check = detector.get_bool_from_os(dependency)
            # Enable the possibility to depend on not having a variable
            if negate.lower() == 'not':
                check = not check

            # Skip if not meeting the requirements of the dependency
            if not check:
                if not self._testing:
                    log.debug("Skip '%s': unmet %s", apiclass_module, dependency)
                return endpoint

        # Get the class from the module
        endpoint.cls = meta.get_class_from_string(class_name, module)
        if endpoint.cls is None:
            log.critical("Could not extract python class '%s'", class_name)
            return endpoint
        else:
            endpoint.exists = True

        # Is this a base or a custom class?
        endpoint.iscore = iscore

        # DEPRECATED
        # endpoint.instance = endpoint.cls()

        # Global tags
        # to be applied to all methods
        endpoint.tags = conf.pop('labels', [])

        # base URI
        base = conf.pop('baseuri', API_URL)
        if base not in BASE_URLS:
            log.warning("Invalid base %s", base)
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
            'publish': {},
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

                endpoint.custom['schema']['publish'][label] = schema.get(
                    'publish', False
                )

                self._schemas_map[schema_uri] = total_uri

        # Check if something strange is still in configuration
        if len(conf) > 0:
            raise KeyError("Unwanted keys: %s" % list(conf.keys()))

        return endpoint
