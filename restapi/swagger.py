"""
Integrating swagger in automatic ways.
Original source was:
https://raw.githubusercontent.com/gangverk/flask-swagger/master/flask_swagger.py

"""

import json
import os
import re

from bravado_core.spec import Spec
from bravado_core.validate import validate_object

from restapi.confs import (
    CUSTOM_PACKAGE,
    EXTENDED_PACKAGE,
    EXTENDED_PROJECT_DISABLED,
    MODELS_DIR,
    PRODUCTION,
    get_project_configuration,
)
from restapi.utilities.configuration import load_yaml_file, mix
from restapi.utilities.globals import mem
from restapi.utilities.logs import log

JSON_APPLICATION = "application/json"

# Flask accepts the following types:
# https://exploreflask.com/en/latest/views.html
#   string  Accepts any text without a slash (the default).
#   int Accepts integers.
#   float   Like int but for floating point values.
#   path    Like string but accepts slashes.
# Swagger accepts the following types:
# https://swagger.io/specification/#data-types-12
FLASK_TO_SWAGGER_TYPES = {
    "string": "string",
    "path": "string",
    "int": "integer",
    "float": "number",
}


# to be deprecated
def input_validation(json_parameters, definitionName):  # pragma: no cover

    definition = mem.customizer.swagger_specs["definitions"][definitionName]
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
        self._used_swagger_tags = set()
        self._private_endpoints = {}

    @staticmethod
    def split_parameter(parameter):

        # No type specified, default to string
        if ":" not in parameter:
            parameter = f"string:{parameter}"

        parameter = parameter.split(":")

        parameter[0] = FLASK_TO_SWAGGER_TYPES.get(parameter[0], "string")
        return parameter[0], parameter[1]

    def read_my_swagger(self, method, endpoint, mapping):

        if not isinstance(mapping, dict):  # pragma: no cover
            raise TypeError(f"Wrong type: {type(mapping)}")

        if len(mapping) < 1:  # pragma: no cover
            raise ValueError(f"No definition found in: {mapping}")

        # Specs should contain only labels written in spec before

        pattern = re.compile(r"\<([^\>]+)\>")

        for label, specs in mapping.items():

            uri = f"/{endpoint.base_uri}{label}"
            # This will be used by server.py.add
            endpoint.uris.setdefault(uri, uri)
            specs.setdefault("parameters", [])
            newuri = uri[:]  # create a copy

            # Deprecated since 0.7.4
            custom_specs = specs.pop("custom", None)
            if custom_specs is not None:  # pragma: no cover
                log.warning("Deprecated use of custom in specs")

            # Deprecated since 0.7.4
            cparam = specs.pop("custom_parameters", None)
            if cparam is not None:  # pragma: no cover
                log.warning("Deprecated use of custom in specs")

            private = specs.pop("private", False)
            self._private_endpoints.setdefault(uri, {})
            self._private_endpoints[uri].setdefault(method, private)

            ###########################
            # Read normal parameters
            for parameter in pattern.findall(uri):

                ptype, pname = self.split_parameter(parameter)

                specs["parameters"].append(
                    {"name": pname, "type": ptype, "in": "path", "required": True}
                )
                # replace in a new uri
                # <param> -> {param}
                newuri = newuri.replace(f"<{parameter}>", f"{{{pname}}}")

            # cycle parameters and add them to the endpoint class
            for param in specs["parameters"]:

                # Remove custom attributes from parameters to prevent validation errors
                param.pop("custom", None)

                enum = param.pop("enum", None)
                # to be deprecated
                if enum is not None:  # pragma: no cover
                    param["enum"] = []
                    for option in enum:
                        if isinstance(option, str):
                            param["enum"].append(option)
                        else:
                            # enum [{key1: value1}, {key2: value2}]
                            # became enum [key1, ke2]
                            for k in option:
                                param["enum"].append(k)

                # Deprecated since 0.7.4
                if param["in"] == "query":  # pragma: no cover
                    log.warning(
                        "{}.py: deprecated query parameter '{}' in {} {}",
                        endpoint.cls.__name__,
                        param.get("name"),
                        method.upper(),
                        label,
                    )

            # Swagger does not like empty arrays
            if len(specs["parameters"]) < 1:
                specs.pop("parameters")

            ##################
            # Save definition for checking
            self._original_paths.setdefault(uri, {})
            self._original_paths[uri][method] = specs

            # Handle global tags
            if endpoint.tags:
                specs.setdefault("tags", list())
                specs["tags"] = list(set(specs["tags"] + endpoint.tags))
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

    def swaggerish(self):
        """
        Go through all endpoints configured by the current development.

        Provide the minimum required data according to swagger specs.
        """

        # Better chosen dinamically from endpoint.py
        schemes = ["http"]
        if PRODUCTION:
            schemes = ["https"]

        # A template base
        output = {
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

        version = get_project_configuration("project.version")
        title = get_project_configuration("project.title")

        if version is not None:
            output["info"]["version"] = version
        if title is not None:
            output["info"]["title"] = title

        ###################
        models = self.get_models()
        self._fdp = models.pop("FormDataParameters", {})

        for k in ["definitions", "parameters", "responses"]:
            if k in models:
                output[k] = models.get(k, {})

        output["consumes"] = [
            JSON_APPLICATION,
            # required for parameters with "in: formData"
            "application/x-www-form-urlencoded",
            # required for parameters of "type: file"
            "multipart/form-data",
        ]
        output["produces"] = [JSON_APPLICATION]

        ###################
        # Read endpoints swagger files
        for key, endpoint in enumerate(self._endpoints):

            for method, mapping in endpoint.methods.items():
                # add the custom part to the endpoint

                self._endpoints[key] = self.read_my_swagger(method, endpoint, mapping)

        self._customizer._private_endpoints = self._private_endpoints
        output["paths"] = self._paths

        ###################
        tags = []
        for tag, desc in mem.configuration["tags"].items():
            if tag not in self._used_swagger_tags:
                log.debug("Skipping unsed tag: {}", tag)
                continue
            tags.append({"name": tag, "description": desc})

        # Also used in NEW swagger specs
        mem.configuration["cleaned_tags"] = tags

        output["tags"] = tags

        self._customizer._original_paths = self._original_paths
        return output

    @staticmethod
    def get_models():
        """ Read swagger.yaml models from extended and custom projects """

        # CUSTOM definitions
        path = os.path.join(os.curdir, CUSTOM_PACKAGE, MODELS_DIR)
        try:
            models = load_yaml_file("swagger.yaml", path=path)
        except AttributeError as e:
            log.verbose(e)
            models = {}

        if EXTENDED_PACKAGE == EXTENDED_PROJECT_DISABLED:
            return models

        path = os.path.join(os.curdir, EXTENDED_PACKAGE, MODELS_DIR)
        try:
            base_models = load_yaml_file("swagger.yaml", path=path)
            return mix(base_models, models)
        except AttributeError as e:
            log.verbose(e)

        return models

    def validation(self, swag_dict):
        """
        Based on YELP library,
        verify the current definition on the open standard
        """

        if len(swag_dict["paths"]) < 1:
            raise AttributeError("Swagger 'paths' definition is empty")

        bravado_config = {
            "validate_swagger_spec": True,
            "validate_requests": False,
            "validate_responses": False,
            "use_models": False,
        }

        try:
            swag_dict = json.loads(json.dumps(swag_dict))
            self._customizer._validated_spec = Spec.from_dict(
                swag_dict, config=bravado_config
            )
            log.debug("Swagger configuration is validated")
        except Exception as e:  # pragma: no cover
            error = str(e).split("\n")[0]
            log.error("Failed to validate:\n{}\n", error)
            return False

        return True
