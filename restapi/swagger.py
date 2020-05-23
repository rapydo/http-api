# -*- coding: utf-8 -*-

"""
Integrating swagger in automatic ways.
Original source was:
https://raw.githubusercontent.com/gangverk/flask-swagger/master/flask_swagger.py

"""

import re
import os
import json
from bravado_core.spec import Spec
from bravado_core.validate import validate_object

from restapi.confs import PRODUCTION, ABS_RESTAPI_PATH, MODELS_DIR
from restapi.confs import CUSTOM_PACKAGE, EXTENDED_PACKAGE, EXTENDED_PROJECT_DISABLED
from restapi.confs import get_project_configuration
from restapi.utilities.globals import mem
from restapi.utilities.configuration import load_yaml_file, mix
from restapi.utilities.logs import log

JSON_APPLICATION = 'application/json'


def input_validation(json_parameters, definitionName):

    definition = mem.customizer._definitions['definitions'][definitionName]
    spec = mem.customizer._validated_spec

    # Can raise jsonschema.exceptions.ValidationError
    validate_object(spec, definition, json_parameters)


class Swagger:
    """Swagger class in our own way:

    Fewer methods than the original swagger reading,
    also more control and closer to the original swagger.
    """

    def __init__(self, endpoints, customizer):

        # Input
        self._endpoints = endpoints
        self._customizer = customizer

        # Swagger paths
        self._paths = {}
        # Original paths as flask should map
        self._original_paths = {}
        # The complete set of query parameters for all classes
        self._qparams = {}
        # Save schemas for parameters before to remove the custom sections
        # It is used to provide schemas for unittests and automatic forms
        # To be deprecated: only used by IMC, once converted remove this
        self._parameter_schemas = {}
        self._used_swagger_tags = set()

    def read_my_swagger(self, method, endpoint, mapping=None):

        if not isinstance(mapping, dict):
            raise TypeError("Wrong type: {}".format(type(mapping)))

        if len(mapping) < 1:
            raise ValueError("No definition found in: {}".format(mapping))

        # Specs should contain only labels written in spec before

        pattern = re.compile(r'\<([^\>]+)\>')

        for label, specs in mapping.items():

            uri = '/{}{}'.format(endpoint.base_uri, label)
            # This will be used by server.py.add
            endpoint.uris.setdefault(uri, uri)

            # Separate external definitions

            # Find any custom part which is not swagger definition
            # Deprecated since 0.7.4
            if 'custom' in specs:
                log.warning("Deprecated use of custom in specs")
                specs.pop('custom', {})

            ###########################
            # Strip the uri of the parameter
            # and add it to 'parameters'
            newuri = uri[:]  # create a copy
            specs.setdefault('parameters', [])

            ###########################
            # Read Form Data Custom parameters
            # TO BE DEPRECATED AFTER APISPEC
            # Already removed from core
            cparam = specs.pop('custom_parameters', None)
            if cparam is not None:
                for fdp in cparam:

                    params = self._fdp.get(fdp)
                    if params is None:
                        log.exit("No custom form data '{}'", fdp)
                    else:
                        # Unable to extend with list by using extends() because
                        # it add references to the original object and do not
                        # create copies. Without copying, the same objects will
                        # be modified several times leading to errors
                        for p in params:
                            specs['parameters'].append(p.copy())

            ###########################
            # Read normal parameters
            for parameter in pattern.findall(uri):

                # create parameters
                x = parameter.split(':')
                xlen = len(x)
                paramtype = 'string'

                if xlen == 1:
                    paramname = x[0]
                elif xlen == 2:
                    paramtype = x[0]
                    paramname = x[1]

                # FIXME: complete for all types
                # http://swagger.io/specification/#data-types-12
                if paramtype == 'int':
                    paramtype = 'number'
                if paramtype == 'path':
                    paramtype = 'string'

                path_parameter = {
                    'name': paramname,
                    'type': paramtype,
                    'in': 'path',
                    'required': True,
                }

                specs['parameters'].append(path_parameter)

                # replace in a new uri
                # <param> -> {param}
                newuri = newuri.replace(
                    '<{}>'.format(parameter), '{{{}}}'.format(paramname))

            # cycle parameters and add them to the endpoint class
            query_params = []
            for param in specs['parameters']:

                if param["in"] != 'path':
                    self._parameter_schemas.setdefault(uri, {})
                    self._parameter_schemas[uri].setdefault(method, [])
                    self._parameter_schemas[uri][method].append(param.copy())

                # Remove custom attributes from parameters to prevent validation errors
                param.pop('custom', None)

                enum = param.pop("enum", None)
                if enum is not None:
                    param["enum"] = []
                    for option in enum:
                        if isinstance(option, str):
                            param["enum"].append(option)
                        else:
                            # enum [{key1: value1}, {key2: value2}]
                            # became enum [key1, ke2]
                            for k in option:
                                param["enum"].append(k)

                # handle parameters in URI for Flask
                if param['in'] == 'query':
                    query_params.append(param)

            if len(query_params) > 0:
                self.query_parameters(
                    endpoint.cls, method=method, uri=uri, params=query_params
                )

            # Swagger does not like empty arrays
            if len(specs['parameters']) < 1:
                specs.pop('parameters')

            ##################
            # Save definition for checking
            self._original_paths.setdefault(uri, {})
            self._original_paths[uri][method] = specs

            # Handle global tags
            if endpoint.tags:
                specs.setdefault('tags', list())
                specs['tags'].extend(endpoint.tags)
                # A global set with all used occurrences
                self._used_swagger_tags.update(endpoint.tags)

            ##################
            # NOTE: whatever is left inside 'specs' will be
            # passed later on to Swagger Validator...

            # Save definition for publishing
            self._paths.setdefault(newuri, {})
            self._paths[newuri][method] = specs

            log.verbose("Built definition '{}:{}'", method.upper(), newuri)

        return endpoint

    def query_parameters(self, cls, method, uri, params):
        """
        apply decorator to endpoint for query parameters
        # self._params[classname][URI][method][name]
        """

        clsname = cls.__name__
        self._qparams.setdefault(clsname, {})
        self._qparams[clsname].setdefault(uri, {})
        self._qparams[clsname][uri].setdefault(method, {})

        for param in params:
            self._qparams[clsname][uri][method].setdefault(
                param['name'],
                param
            )

    def swaggerish(self):
        """
        Go through all endpoints configured by the current development.

        Provide the minimum required data according to swagger specs.
        """

        # Better chosen dinamically from endpoint.py
        schemes = ['http']
        if PRODUCTION:
            schemes = ['https']

        # A template base
        output = {
            # TODO: update to 3.0.1? Replace bravado with something else?
            # https://github.com/Yelp/bravado/issues/306
            "swagger": "2.0",
            "info": {"version": "0.0.1", "title": "Your application name"},
            "schemes": schemes,
            # "host": "localhost"  # chosen dinamically
            "basePath": "/",
            "securityDefinitions": {
                "Bearer": {"type": "apiKey", "name": "Authorization", "in": "header"}
            },
            "security": [{"Bearer": []}],
        }

        version = get_project_configuration('project.version')
        title = get_project_configuration('project.title')

        if version is not None:
            output['info']['version'] = version
        if title is not None:
            output['info']['title'] = title

        ###################
        models = self.get_models()
        self._fdp = models.pop('FormDataParameters', {})

        for k in ["definitions", "parameters", "responses"]:
            if k in models:
                output[k] = models.get(k, {})

        output['consumes'] = [
            JSON_APPLICATION,
            # required for parameters with "in: formData"
            "application/x-www-form-urlencoded",
            # required for parameters of "type: file"
            "multipart/form-data"
        ]
        output['produces'] = [JSON_APPLICATION]

        ###################
        # Read endpoints swagger files
        for key, endpoint in enumerate(self._endpoints):

            for method, mapping in endpoint.methods.items():
                # add the custom part to the endpoint

                self._endpoints[key] = self.read_my_swagger(
                    method, endpoint, mapping
                )

        ###################
        # Save query parameters globally
        self._customizer._query_params = self._qparams
        self._customizer._parameter_schemas = self._parameter_schemas
        output['paths'] = self._paths

        ###################
        tags = []
        for tag, desc in self._customizer._configurations['tags'].items():
            if tag not in self._used_swagger_tags:
                log.debug("Skipping unsed tag: {}", tag)
                continue
            tags.append({'name': tag, 'description': desc})
        output['tags'] = tags

        self._customizer._original_paths = self._original_paths
        return output

    @staticmethod
    def get_models():
        """ Read swagger.yaml models from extended and custom projects """

        # CUSTOM definitions
        path = os.path.join(os.curdir, CUSTOM_PACKAGE, MODELS_DIR)
        try:
            models = load_yaml_file('swagger.yaml', path=path)
        except AttributeError as e:
            log.verbose(e)
            models = {}

        if EXTENDED_PACKAGE == EXTENDED_PROJECT_DISABLED:
            return models

        path = os.path.join(os.curdir, EXTENDED_PACKAGE, MODELS_DIR)
        try:
            base_models = load_yaml_file('swagger.yaml', path=path)
            return mix(base_models, models)
        except AttributeError as e:
            log.verbose(e)

        return models

    def validation(self, swag_dict):
        """
        Based on YELP library,
        verify the current definition on the open standard
        """

        if len(swag_dict['paths']) < 1:
            raise AttributeError("Swagger 'paths' definition is empty")

        # filepath = os.path.join(tempfile.gettempdir(), 'test.json')

        # try:
        #     # Fix jsonschema validation problem
        #     # expected string or bytes-like object
        #     # http://j.mp/2hEquZy
        #     swag_dict = json.loads(json.dumps(swag_dict))
        #     # write it down
        #     # FIXME: can we do better than this?
        #     with open(filepath, 'w') as f:
        #         json.dump(swag_dict, f)
        # except Exception as e:
        #     raise e
        #     # log.warning("Failed to temporary save the swagger definition")

        bravado_config = {
            'validate_swagger_spec': True,
            'validate_requests': False,
            'validate_responses': False,
            'use_models': False,
        }

        try:
            swag_dict = json.loads(json.dumps(swag_dict))
            self._customizer._validated_spec = Spec.from_dict(
                swag_dict, config=bravado_config
            )
            log.debug("Swagger configuration is validated")
        except Exception as e:
            # raise e
            error = str(e).split('\n')[0]
            log.error("Failed to validate:\n{}\n", error)
            return False
        # finally:
        #     os.remove(filepath)

        return True
