"""
Integrating swagger in automatic ways.
Original source was:
https://raw.githubusercontent.com/gangverk/flask-swagger/master/flask_swagger.py

"""

import re

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


# Deprecated since 0.7.6
def input_validation(json_parameters, definitionName):  # pragma: no cover
    log.critical("Deprecated use of input_validation, use webargs instead")


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

                specs.setdefault("parameters", [])
                specs["parameters"].append(
                    {"name": pname, "type": ptype, "in": "path", "required": True}
                )
                # replace in a new uri
                # <param> -> {param}
                newuri = newuri.replace(f"<{parameter}>", f"{{{pname}}}")

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

        # Read endpoints swagger files
        for key, endpoint in enumerate(self._endpoints):

            for method, mapping in endpoint.methods.items():
                # add the custom part to the endpoint

                self._endpoints[key] = self.read_my_swagger(method, endpoint, mapping)

        self._customizer._private_endpoints = self._private_endpoints

        ###################
        tags = []
        for tag, desc in mem.configuration["tags"].items():
            if tag not in self._used_swagger_tags:
                log.debug("Skipping unsed tag: {}", tag)
                continue
            tags.append({"name": tag, "description": desc})

        # Also used in NEW swagger specs
        mem.configuration["cleaned_tags"] = tags

        self._customizer._original_paths = self._original_paths
