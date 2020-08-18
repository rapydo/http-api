"""
Customization based on configuration 'blueprint' files
"""

import copy
import glob
import os
import re

from attr import ib as attribute
from attr import s as ClassOfAttributes
from flask.views import MethodViewType
from flask_apispec.utils import Annotation
from flask_apispec.views import MethodResourceMeta

from restapi import decorators
from restapi.confs import (
    ABS_RESTAPI_PATH,
    API_URL,
    BASE_URLS,
    CONF_PATH,
    CUSTOM_PACKAGE,
)
from restapi.env import Env
from restapi.services.detect import detector  # do not remove this unused import
from restapi.utilities.configuration import read_configuration
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

CONF_FOLDERS = Env.load_group(label="project_confs")

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

uri_pattern = re.compile(r"\<([^\>]+)\>")

log.verbose("Detector loaded: {}", detector)


@ClassOfAttributes
class EndpointElements:
    cls = attribute(default=None)
    uris = attribute(default={})
    methods = attribute(default={})
    tags = attribute(default=[])
    base_uri = attribute(default="")
    private = attribute(default=False)


class Customizer:
    def __init__(self):

        self._endpoints = []
        self._authenticated_endpoints = {}
        self._private_endpoints = {}
        self._original_paths = {}

    def load_configuration(self):
        # Reading configuration
        confs_path = os.path.join(os.curdir, CONF_PATH)
        defaults_path = CONF_FOLDERS.get("defaults_path", confs_path)
        base_path = CONF_FOLDERS.get("base_path", confs_path)
        projects_path = CONF_FOLDERS.get("projects_path", confs_path)
        submodules_path = CONF_FOLDERS.get("submodules_path", confs_path)

        try:
            configuration, self._extended_project, _ = read_configuration(
                default_file_path=defaults_path,
                base_project_path=base_path,
                projects_path=projects_path,
                submodules_path=submodules_path,
            )
        except AttributeError as e:  # pragma: no cover
            log.exit(e)

        return configuration

    @staticmethod
    def skip_endpoint(depends_on):
        for var in depends_on:
            pieces = var.strip().split(" ")
            pieces_num = len(pieces)
            if pieces_num == 1:
                dependency = pieces.pop()
                negate = False
            elif pieces_num == 2:
                negate, dependency = pieces
                negate = negate.lower() == "not"
            else:  # pragma: no cover
                log.exit("Wrong depends_on parameter: {}", var)

            check = Env.get_bool(dependency)
            if negate:
                check = not check

            # Skip if not meeting the requirements of the dependency
            if not check:
                return True, dependency

        return False, None

    @staticmethod
    def inject_apispec_docs(fn, conf, labels):
        # retrieve attributes already set with @docs decorator
        fn.__apispec__ = fn.__dict__.get("__apispec__", {})
        docs = {}
        for doc in fn.__apispec__["docs"]:
            docs.update(doc.options[0])

        missing = {}
        if "summary" not in docs:
            summary = conf.get("summary")
            if summary is not None:
                missing["summary"] = summary
        if "description" not in docs:
            description = conf.get("description")
            if description is not None:
                missing["description"] = description
        if "tags" not in docs:
            if labels:
                missing["tags"] = labels

        if "responses" not in docs:
            responses = conf.get("responses")
            if responses is not None:
                missing["responses"] = responses

        if "responses" in docs:
            responses = conf.get("responses")
            if responses is not None:
                for code, resp in responses.items():
                    if code not in docs["responses"]:
                        missing.setdefault("responses", {})
                        missing["responses"][code] = resp

        # mimic the behaviour of @docs decorator
        # https://github.com/jmcarp/flask-apispec/...
        #                         .../flask_apispec/annotations.py
        annotation = Annotation(
            options=[missing],
            # Inherit Swagger documentation from parent classes
            # None is the default value
            inherit=None,
        )
        fn.__apispec__["docs"].insert(0, annotation)

    def load_endpoints(self):

        ##################
        # Walk folders looking for endpoints

        endpoints_folders = []
        # core endpoints folder (rapydo/http-api)
        endpoints_folders.append(ABS_RESTAPI_PATH)

        # endpoints folder from extended project, if any
        if self._extended_project is not None:
            endpoints_folders.append(os.path.join(os.curdir, self._extended_project))

        # custom endpoints folder
        endpoints_folders.append(os.path.join(os.curdir, CUSTOM_PACKAGE))

        ERROR_401 = {
            "description": "This endpoint requires a valid authorization token"
        }
        ERROR_400 = {
            "description": "The request cannot be satisfied due to malformed syntax"
        }
        ERROR_404 = {"description": "The requested resource cannot be found"}
        ERROR_404_AUTH = {
            "description": "The resource cannot be found or you are not authorized"
        }

        used_tags = set()
        for base_dir in endpoints_folders:

            # get last item of the path
            # normapath is required to strip final / is any
            base_module = os.path.basename(os.path.normpath(base_dir))

            apis_dir = os.path.join(base_dir, "endpoints")
            apiclass_module = f"{base_module}.endpoints"

            # Looking for all file in apis folder
            for epfiles in glob.glob(f"{apis_dir}/*.py"):

                # get module name (es: apis.filename)
                module_file = os.path.basename(os.path.splitext(epfiles)[0])
                module_name = f"{apiclass_module}.{module_file}"
                # Convert module name into a module
                log.debug("Importing {}", module_name)
                module = Meta.get_module_from_string(module_name, exit_on_fail=True,)

                # Extract classes from the module
                classes = Meta.get_new_classes_from_module(module)
                for class_name, epclss in classes.items():
                    # Filtering out classes without expected data
                    if not hasattr(epclss, "methods") or epclss.methods is None:
                        continue

                    log.debug(
                        "Importing {} from {}.{}", class_name, apis_dir, module_file
                    )

                    skip, dependency = self.skip_endpoint(epclss.depends_on)

                    if skip:
                        log.debug(
                            "Skipping '{} {}' due to unmet dependency: {}",
                            module_name,
                            class_name,
                            dependency,
                        )
                        continue

                    if epclss.baseuri in BASE_URLS:
                        base = epclss.baseuri
                    else:
                        log.warning("Invalid base {}", epclss.baseuri)
                        base = API_URL
                    base = base.strip("/")

                    # Building endpoint
                    endpoint = EndpointElements(
                        uris={},
                        methods={},
                        cls=epclss,
                        tags=epclss.labels,
                        base_uri=base,
                        private=epclss.private,
                    )

                    mapping_lists = []
                    for m in epclss.methods:
                        method_name = f"_{m}"
                        if not hasattr(epclss, method_name):

                            method_name = m
                            if not hasattr(epclss, method_name):
                                log.warning(
                                    "{} configuration not found in {}", m, class_name
                                )
                                continue
                            # convert GET -> _GET
                            # Deprecated since 0.7.4
                            else:  # pragma: no cover
                                log.warning("Obsolete dict {} in {}", m, class_name)

                        # get, post, put, patch, delete
                        method_fn = m.lower()

                        # conf from GET, POST, ... dictionaries
                        conf = getattr(epclss, method_name)
                        # endpoint uris /api/bar, /api/food
                        kk = conf.keys()

                        # get, post, put, patch, delete functions
                        fn = getattr(epclss, method_fn)

                        # Adding the catch_errors decorator to every endpoint
                        # I'm using a magic bool variabile to be able to raise warning
                        # in case of the normal [deprecated] use
                        decorator = decorators.catch_errors(magic=True)
                        setattr(epclss, method_fn, decorator(fn))

                        # auth.required injected by the required decorator in bearer.py
                        auth_required = fn.__dict__.get("auth.required", False)
                        for u in conf:
                            conf[u].setdefault("responses", {})

                            full_uri = f"/{base}{u}"
                            self._authenticated_endpoints.setdefault(full_uri, {})
                            # method_fn is equivalent to m.lower()
                            self._authenticated_endpoints[full_uri].setdefault(
                                method_fn, auth_required
                            )

                            conf[u]["responses"].setdefault("400", ERROR_400)
                            if auth_required:
                                conf[u]["responses"].setdefault("401", ERROR_401)
                                conf[u]["responses"].setdefault("404", ERROR_404_AUTH)
                            else:
                                conf[u]["responses"].setdefault("404", ERROR_404)
                            # inject _METHOD dictionaries into __apispec__ attribute
                            # __apispec__ is normally populated by using @docs decorator
                            if isinstance(epclss, MethodResourceMeta):
                                self.inject_apispec_docs(fn, conf[u], epclss.labels)
                            elif not isinstance(epclss, MethodViewType):
                                log.warning(  # pragma: no cover
                                    "Unknown class type: {}", type(epclss)
                                )

                            mapping_lists.extend(kk)
                            mapping = copy.deepcopy(conf)
                            endpoint.methods[method_fn] = mapping

                            for label, specs in mapping.items():

                                uri = f"/{endpoint.base_uri}{label}"
                                # This will be used by server.py.add
                                endpoint.uris.setdefault(uri, uri)

                                self._private_endpoints.setdefault(uri, {})
                                self._private_endpoints[uri].setdefault(
                                    method_fn, endpoint.private
                                )

                                # Read URL parameters
                                for parameter in uri_pattern.findall(uri):

                                    # No type specified, default to string
                                    if ":" not in parameter:
                                        ptype = "string"
                                        pname = parameter
                                    else:
                                        ptokens = parameter.split(":")
                                        ptype = FLASK_TO_SWAGGER_TYPES.get(
                                            ptokens[0], "string"
                                        )
                                        pname = ptokens[1]

                                    specs.setdefault("parameters", [])
                                    specs["parameters"].append(
                                        {
                                            "name": pname,
                                            "type": ptype,
                                            "in": "path",
                                            "required": True,
                                        }
                                    )

                                # Save definition for checking
                                self._original_paths.setdefault(uri, {})
                                self._original_paths[uri][method_fn] = specs

                                # Handle global tags
                                if endpoint.tags:
                                    specs.setdefault("tags", list())
                                    specs["tags"] = list(
                                        set(specs["tags"] + endpoint.tags)
                                    )

                                log.verbose("Built definition '{}:{}'", m, uri)

                            used_tags.update(endpoint.tags)
                    self._endpoints.append(endpoint)

        tags = []
        for tag, desc in mem.configuration["tags"].items():
            if tag not in used_tags:
                log.debug("Skipping unsed tag: {}", tag)
                continue
            tags.append({"name": tag, "description": desc})

        # Used in swagger specs endpoint
        mem.configuration["cleaned_tags"] = tags

        # Verify for mapping duplication or shadowing
        # Example of shadowing:
        # /xyz/<variable>
        # /xyz/abc
        # The second endpoint is shadowed by the first one
        mappings = {}
        classes = {}
        # duplicates are found while filling the dictionaries
        for endpoint in self._endpoints:
            for method, uris in endpoint.methods.items():
                mappings.setdefault(method, set())
                classes.setdefault(method, {})

                for uri in uris.keys():
                    uri = f"/{endpoint.base_uri}{uri}"
                    if uri in mappings[method]:
                        log.warning(
                            "Endpoint redefinition: {} {} used from both {} and {}",
                            method.upper(),
                            uri,
                            endpoint.cls.__name__,
                            classes[method][uri].__name__,
                        )
                    else:
                        mappings[method].add(uri)
                        classes[method][uri] = endpoint.cls

        # Detect endpoints swadowing
        for method, uris in mappings.items():
            for idx1, u1 in enumerate(uris):
                for idx2, u2 in enumerate(uris):
                    # Just skip checks of an element with it-self (same index)
                    # or elements already verified (idx2 < idx1)
                    if idx2 <= idx1:
                        continue

                    # split url tokens and remove the first (always empty) token
                    u1_tokens = u1.split("/")[1:]
                    u2_tokens = u2.split("/")[1:]
                    # If number of tokens differens, there cannot be any collision
                    if len(u1_tokens) != len(u2_tokens):
                        continue
                    # verify is base uri is the same or not
                    if u1_tokens[0] != u2_tokens[0]:
                        continue
                    # strip off base uri
                    u1_tokens = u1_tokens[1:]
                    u2_tokens = u2_tokens[1:]

                    is_safe = False
                    for index, t1 in enumerate(u1_tokens):
                        t2 = u2_tokens[index]
                        fixed_token1 = not t1.startswith("<")
                        fixed_token2 = not t2.startswith("<")
                        # the safe if tokens are different and not variable
                        if t1 != t2 and fixed_token1 and fixed_token2:
                            is_safe = True
                            break
                    if not is_safe:
                        log.warning(
                            "Endpoint shadowing detected: {}({m} {}) and {}({m} {})",
                            classes[method][u1].__name__,
                            u1,
                            classes[method][u2].__name__,
                            u2,
                            m=method.upper(),
                        )
