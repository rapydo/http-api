from typing import Any, Dict, List

from flask import jsonify
from glom import glom

from restapi import decorators
from restapi.rest.definition import EndpointResource
from restapi.utilities.globals import mem
from restapi.utilities.logs import log


class NewSwaggerSpecifications(EndpointResource):
    """
    Specifications output throught Swagger (open API) standards
    """

    labels = ["specifications"]

    @decorators.endpoint(
        path="/swagger",
        summary="Endpoints specifications based on OpenAPI format",
        responses={200: "Endpoints JSON based on OpenAPI Specifications"},
    )
    @decorators.endpoint(
        path="/specs",
        summary="Endpoints specifications based on OpenAPI format",
        responses={200: "Endpoints JSON based on OpenAPI Specifications"},
    )
    def get(self):

        specs = mem.docs.spec.to_dict()

        user = self.get_user_if_logged(allow_access_token_parameter=True)
        if user:
            # Set security requirements for endpoint
            for key, data in specs.items():

                # Find endpoint mapping flagged as private
                if key == "paths":
                    for uri, endpoint in data.items():
                        u = uri.replace("{", "<").replace("}", ">")
                        for method, definition in endpoint.items():

                            auth_required = glom(
                                mem.authenticated_endpoints,
                                f"{u}.{method}",
                                default=False,
                            )

                            if auth_required:
                                definition["security"] = [{"Bearer": []}]

            return jsonify(specs)

        log.info("Unauthenticated request, filtering out private endpoints")
        # Remove sensible data
        filtered_specs: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # schemaName => True|False (private|public)
        privatedefs: Dict[str, bool] = {}
        # schemaName => [list of definitions including this]
        parentdefs: Dict[str, List[Any]] = {}
        for key, data in specs.items():

            # Find endpoint mapping flagged as private
            if key == "paths":
                for uri, endpoint in data.items():
                    u = uri.replace("{", "<").replace("}", ">")
                    for method, definition in endpoint.items():

                        is_private = glom(
                            mem.private_endpoints,
                            f"{u}.{method}",
                            default=False,
                        )
                        defs = definition.get("parameters", [])[:]
                        for p in defs:

                            if "schema" not in p:
                                continue
                            if "$ref" not in p["schema"]:
                                continue
                            ref = p["schema"]["$ref"]
                            def_name = ref.replace("#/definitions/", "")

                            privatedefs.setdefault(def_name, True)
                            # Will be True if all occurrences are private
                            privatedefs[def_name] = privatedefs[def_name] and is_private

                        if is_private:
                            log.debug("Skipping {} {}", method, uri)
                            continue

                        auth_required = glom(
                            mem.authenticated_endpoints,
                            f"{u}.{method}",
                            default=False,
                        )

                        if auth_required:
                            definition["security"] = [{"Bearer": []}]

                        filtered_specs.setdefault(key, {})
                        filtered_specs[key].setdefault(uri, {})
                        filtered_specs[key][uri].setdefault(method, definition)

                        # definitions
            elif key == "definitions":

                # Saving definition inclusion, will be used later to determine
                # if a definition is private or not
                # If a definition is referenced by an endpoint, the definition
                # visibility matches the endpoint visibility
                # If a definition is referenced by other definitions, its visibility
                # will be calculated as AND(parent definitions)
                # Verification postponed
                for schema, definition in data.items():
                    # parentdefs
                    for d in definition.get("properties", {}).values():
                        if "$ref" in d:
                            ref = d["$ref"]
                            def_name = ref.replace("#/definitions/", "")

                            parentdefs.setdefault(def_name, [])
                            parentdefs[def_name].append(schema)

            else:
                filtered_specs.setdefault(key, data)

        if "definitions" in specs:

            filtered_specs.setdefault("definitions", {})
            for schema, definition in specs["definitions"].items():

                if self.is_definition_private(schema, privatedefs, parentdefs):
                    log.debug("Skipping private definition {}", schema)
                    continue
                filtered_specs["definitions"].setdefault(schema, definition)

        return jsonify(filtered_specs)

    def is_definition_private(self, schema_name, privatedefs, parentdefs, recursion=0):

        # can be True|False|None
        from_private_endpoint = privatedefs.get(schema_name, None)

        # Can be None|empty list|list
        parents = parentdefs.get(schema_name, None)

        # This definition is not used by any endpoint or other definitions
        # Probably it is used with a marshal_with to serialize a response...
        # Response Schemas are not reported in the spec by FlaskApiSpec
        # so for now let's consider it as private and filter out
        if from_private_endpoint is None and parents is None:
            return True

        # This definition is not used by other definitions => the visibility
        # is only given by endpoints visibility if any
        if not parents and from_private_endpoint is not None:
            return from_private_endpoint

        # parents is not expected to be a non-empty list,
        # otherwise something is going wrong
        # This if should always fail
        if not parents:  # pragma: no cover
            log.warning(
                "Invalid {} definition, unable to determine the visibility {} {}",
                schema_name,
                from_private_endpoint,
                parents,
            )
            # Let's consider it as private and filter it out
            return True

        # Are we in a loop due to a cyclic dependency? Let's stop it
        if recursion > 10:  # pragma: no cover
            # Let's consider it as private and filter it out
            return True

        is_private = True
        for parent in parents:
            priv = self.is_definition_private(
                parent,
                privatedefs,
                parentdefs,
                recursion + 1,  # prevent infinite recursion
            )
            # The definition is private if only included in private definitions
            # If used in at least one public definition, let's consider it as public
            is_private = is_private and priv

        return is_private
