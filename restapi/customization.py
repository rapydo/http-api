# -*- coding: utf-8 -*-

"""
Customization based on configuration 'blueprint' files
"""

import os
import copy

from restapi.confs import API_URL, BASE_URLS, ABS_RESTAPI_PATH, CONF_PATH
from restapi.confs import BACKEND_PACKAGE, CUSTOM_PACKAGE
from restapi.services.detect import detector
from restapi.attributes import EndpointElements, ExtraAttributes
from restapi.swagger import BeSwagger
from restapi.utilities.meta import Meta

from restapi.utilities.configuration import read_configuration
from restapi.utilities.logs import log

meta = Meta()

CONF_FOLDERS = detector.load_group(label='project_confs')


########################
# Customization on the table
########################
class Customizer:
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

        # Reading configuration
        confs_path = os.path.join(os.curdir, CONF_PATH)
        defaults_path = CONF_FOLDERS.get('defaults_path', confs_path)
        base_path = CONF_FOLDERS.get('base_path', confs_path)
        projects_path = CONF_FOLDERS.get('projects_path', confs_path)
        submodules_path = CONF_FOLDERS.get('submodules_path', confs_path)

        try:
            self._configurations, self._extended_project, self._extended_path = \
                read_configuration(
                    default_file_path=defaults_path,
                    base_project_path=base_path,
                    projects_path=projects_path,
                    submodules_path=submodules_path
                )
        except AttributeError as e:
            log.exit(e)

        if not init:
            self.do_schema()
            self.find_endpoints()
            self.do_swagger()

    def do_schema(self):
        """ Schemas exposing, if requested """

        name = '{}.rest.schema'.format(BACKEND_PACKAGE)
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

        # already_loaded = {}
        for folder in endpoints_folders:

            base_dir = folder.get('path')
            iscore = folder.get('iscore')
            # get last item of the path
            # normapath is required to strip final / is any
            base_module = os.path.basename(os.path.normpath(base_dir))

            if iscore:
                apis_dir = os.path.join(base_dir, 'resources')
                apiclass_module = '{}.resources'.format(base_module)
            else:
                apis_dir = os.path.join(base_dir, 'apis')
                apiclass_module = '{}.apis'.format(base_module)

            # Looking for all file in apis folder
            for epfiles in os.listdir(apis_dir):

                # get module name (es: apis.filename)
                module_file = os.path.splitext(epfiles)[0]
                module_name = "{}.{}".format(apiclass_module, module_file)
                # Convert module name into a module
                log.debug("Importing {}", module_name)
                try:
                    module = Meta.get_module_from_string(
                        module_name,
                        exit_on_fail=True,
                        exit_if_not_found=True
                    )
                except BaseException as e:
                    log.exit("Cannot import {}\nError: {}", module_name, e)

                # Extract classes from the module
                # classes = meta.get_classes_from_module(module)
                classes = meta.get_new_classes_from_module(module)
                for class_name in classes:
                    ep_class = classes.get(class_name)
                    # Filtering out classes without required data
                    if not hasattr(ep_class, "methods"):
                        continue
                    if ep_class.methods is None:
                        continue

                    # if class_name in already_loaded:
                    #     log.warning(
                    #         "Skipping import of {} from {}.{}, already loded from {}",
                    #         class_name,
                    #         apis_dir,
                    #         module_file,
                    #         already_loaded[class_name],
                    #     )
                    #     continue
                    # already_loaded[class_name] = "{}.{}".format(apis_dir, module_file)
                    log.debug(
                        "Importing {} from {}.{}", class_name, apis_dir, module_file
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
                                log.exit('Wrong parameter: {}', var)

                            check = detector.get_bool_from_os(dependency)
                            if negate:
                                check = not check

                            # Skip if not meeting the requirements of the dependency
                            if not check:
                                skip = True
                                break

                        if skip:
                            log.debug(
                                "Skipping '{} {}' due to unmet dependency: {}",
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
                        log.warning("Invalid base {}", base)
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
                        method_name = "_{}".format(m)
                        if not hasattr(ep_class, method_name):

                            method_name = m
                            if not hasattr(ep_class, method_name):
                                log.warning(
                                    "{} configuration not found in {}", m, class_name
                                )
                                continue
                            # Enable this warning to start conversions GET -> _GET
                            # Find other warning like this by searching:
                            # **FASTAPI**
                            # else:
                            #     log.warning(
                            #         "Obsolete dict {} in {}", m, class_name
                            #     )

                        conf = getattr(ep_class, method_name)
                        kk = conf.keys()
                        mapping_lists.extend(kk)
                        endpoint.methods[m.lower()] = copy.deepcopy(conf)

                    if endpoint.custom['schema']['expose']:
                        for uri in mapping_lists:
                            total_uri = '/{}{}'.format(endpoint.base_uri, uri)
                            schema_uri = '{}/schemas{}'.format(API_URL, uri)

                            p = hex(id(endpoint.cls))
                            self._schema_endpoint.uris[uri + p] = schema_uri

                            self._schemas_map[schema_uri] = total_uri

                    self._endpoints.append(endpoint)

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
