"""
Customization based on configuration 'blueprint' files
"""

import glob
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Type

from attr import ib as attribute
from attr import s as ClassOfAttributes
from flask_restful import Resource

from restapi import decorators
from restapi.config import (
    ABS_RESTAPI_PATH,
    API_URL,
    BASE_URLS,
    CONF_PATH,
    CUSTOM_PACKAGE,
)
from restapi.env import Env
from restapi.rest.annotations import inject_apispec_docs
from restapi.utilities import print_and_exit
from restapi.utilities.configuration import read_configuration
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

ERR401 = {"description": "This endpoint requires a valid authorization token"}
ERR400 = {"description": "The request cannot be satisfied due to malformed syntax"}
ERR404 = {"description": "The requested resource cannot be found"}
ERR404_AUTH = {"description": "The resource cannot be found or you are not authorized"}

uri_pattern = re.compile(r"\<([^\>]+)\>")


@ClassOfAttributes
class EndpointElements:
    # type of endpoint from flask_restful
    cls: Type[Resource] = attribute(default=None)
    uris: List[str] = attribute(default=[])
    methods: Dict[str, List[str]] = attribute(default={})
    tags: List[str] = attribute(default=[])
    base_uri: str = attribute(default="")
    private: bool = attribute(default=False)


class EndpointsLoader:
    def __init__(self):

        # Used by server.py to load endpoints definitions
        self.endpoints = []
        # Used by server.py to remove unmapped methods
        self.uri2methods = {}
        # Used by server.py to configure ApiSpec
        self.tags = []

        # Used by swagger specs endpoints to show authentication info
        self.authenticated_endpoints = {}
        # Used by swagger spec endpoint to remove private endpoints from public requests
        self.private_endpoints = {}

        self._used_tags = set()

    def load_configuration(self) -> Dict[str, Any]:
        # Reading configuration
        confs_path = Path(os.curdir).joinpath(CONF_PATH)

        CONF_FOLDERS = Env.load_variables_group(prefix="project_confs")
        defaults_path = Path(CONF_FOLDERS.get("defaults_path", confs_path))
        base_path = Path(CONF_FOLDERS.get("base_path", confs_path))
        projects_path = Path(CONF_FOLDERS.get("projects_path", confs_path))
        submodules_path = Path(CONF_FOLDERS.get("submodules_path", confs_path))

        try:
            configuration, self._extended_project, _ = read_configuration(
                default_file_path=defaults_path,
                base_project_path=base_path,
                projects_path=projects_path,
                submodules_path=submodules_path,
            )
        except AttributeError as e:  # pragma: no cover
            print_and_exit(e)

        return configuration

    def load_endpoints(self):

        # core endpoints folder (rapydo/http-api)
        self.load_endpoints_folder(ABS_RESTAPI_PATH)

        # endpoints folder from extended project, if any
        if self._extended_project is not None:
            self.load_endpoints_folder(os.path.join(os.curdir, self._extended_project))

        # custom endpoints folder
        self.load_endpoints_folder(os.path.join(os.curdir, CUSTOM_PACKAGE))

        # Used in swagger specs endpoint
        self.tags = EndpointsLoader.remove_unused_tags(
            mem.configuration["tags"], self._used_tags
        )

        self.detect_endpoints_shadowing()

    @staticmethod
    def skip_endpoint(depends_on):
        for var in depends_on:
            pieces = var.strip().split(" ")
            pieces_num = len(pieces)
            if pieces_num == 1:
                dependency = pieces.pop()
                negate = False
            elif pieces_num == 2:
                neg, dependency = pieces
                negate = neg.lower() == "not"
            else:  # pragma: no cover
                print_and_exit("Wrong depends_on parameter: {}", var)

            check = Env.get_bool(dependency)
            if negate:
                check = not check

            # Skip if not meeting the requirements of the dependency
            if not check:
                return True, dependency

        return False, None

    def extract_endpoints(self, base_dir):

        endpoints_classes = []
        # get last item of the path
        # normpath is required to strip final / if any
        base_module = os.path.basename(os.path.normpath(base_dir))

        apis_dir = os.path.join(base_dir, "endpoints")
        apiclass_module = f"{base_module}.endpoints"
        for epfiles in glob.glob(f"{apis_dir}/*.py"):

            # get module name (es: endpoints.filename)
            module_file = os.path.basename(os.path.splitext(epfiles)[0])
            module_name = f"{apiclass_module}.{module_file}"
            # Convert module name into a module
            log.debug("Importing {}", module_name)
            module = Meta.get_module_from_string(
                module_name,
                exit_on_fail=True,
            )

            # Extract classes from the module
            # module can't be none because of exit_on_fail=True...
            # but my-py can't understand this
            classes = Meta.get_new_classes_from_module(module)  # type: ignore
            for class_name, epclss in classes.items():
                # Filtering out classes without expected data
                if not hasattr(epclss, "methods") or epclss.methods is None:
                    continue

                log.debug("Importing {} from {}.{}", class_name, apis_dir, module_file)

                skip, dependency = self.skip_endpoint(epclss.depends_on)

                if skip:
                    log.debug(
                        "Skipping '{} {}' due to unmet dependency: {}",
                        module_name,
                        class_name,
                        dependency,
                    )
                    continue

                endpoints_classes.append(epclss)

        return endpoints_classes

    def load_endpoints_folder(self, base_dir):
        # Walk folders looking for endpoints

        for epclss in self.extract_endpoints(base_dir):

            if epclss.baseuri in BASE_URLS:
                base = epclss.baseuri
            else:
                log.warning("Invalid base {}", epclss.baseuri)
                base = API_URL
            base = base.strip("/")

            # Building endpoint
            endpoint = EndpointElements(
                uris=[],
                methods={},
                cls=epclss,
                tags=epclss.labels,
                base_uri=base,
                private=epclss.private,
            )

            # m = GET|PUT|POST|DELETE|PATCH|...
            for m in epclss.methods:

                # method_fn = get|post|put|delete|patch|...
                method_fn = m.lower()

                # get, post, put, patch, delete functions
                fn = getattr(epclss, method_fn)

                # Adding the catch_exceptions decorator to every endpoint
                decorator = decorators.catch_exceptions()
                setattr(epclss, method_fn, decorator(fn))

                # auth.required injected by the required decorator in bearer.py
                auth_required = fn.__dict__.get("auth.required", False)

                # auth.optional injected by the optional decorator in bearer.py
                auth_optional = fn.__dict__.get("auth.optional", False)

                if not hasattr(fn, "uris"):  # pragma: no cover
                    print_and_exit(
                        "Invalid {} endpoint in {}: missing endpoint decorator",
                        method_fn,
                        epclss.__name__,
                    )
                    continue

                endpoint.methods[method_fn] = fn.uris
                for uri in fn.uris:

                    full_uri = f"/{endpoint.base_uri}{uri}"
                    self.authenticated_endpoints.setdefault(full_uri, {})
                    # method_fn is equivalent to m.lower()
                    self.authenticated_endpoints[full_uri].setdefault(
                        method_fn, auth_required
                    )

                    # Set default responses
                    responses: Dict[str, Dict[str, str]] = {}

                    responses.setdefault("400", ERR400)
                    if auth_required:
                        responses.setdefault("401", ERR401)
                        responses.setdefault("404", ERR404_AUTH)
                    elif auth_optional:
                        responses.setdefault("401", ERR401)
                        responses.setdefault("404", ERR404)
                    else:
                        responses.setdefault("404", ERR404)
                    # inject _METHOD dictionaries into __apispec__ attribute
                    # __apispec__ is normally populated by using @docs decorator
                    inject_apispec_docs(fn, {"responses": responses}, epclss.labels)

                    # This will be used by server.py.add
                    endpoint.uris.append(full_uri)

                    self.private_endpoints.setdefault(full_uri, {})
                    self.private_endpoints[full_uri].setdefault(
                        method_fn, endpoint.private
                    )

                    # Used by server.py to remove unmapped methods
                    self.uri2methods.setdefault(full_uri, [])
                    self.uri2methods[full_uri].append(method_fn)

                    # log.debug("Built definition '{}:{}'", m, full_uri)

                    self._used_tags.update(endpoint.tags)
            self.endpoints.append(endpoint)

    @staticmethod
    def remove_unused_tags(all_tags, used_tags):
        tags = []
        for tag, desc in all_tags.items():
            if tag not in used_tags:
                log.debug("Skipping unsed tag: {}", tag)
                continue
            tags.append({"name": tag, "description": desc})
        return tags

    def detect_endpoints_shadowing(self):
        # Verify mapping duplication or shadowing
        # Example of shadowing:
        # /xyz/<variable>
        # /xyz/abc
        # The second endpoint is shadowed by the first one
        mappings: Dict[str, Set[str]] = {}
        classes: Dict[str, Dict[str, Type[Resource]]] = {}
        # duplicates are found while filling the dictionaries
        for endpoint in self.endpoints:
            for method, uris in endpoint.methods.items():
                mappings.setdefault(method, set())
                classes.setdefault(method, {})

                for uri in uris:
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
