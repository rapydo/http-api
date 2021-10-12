"""

Customization based on configuration 'blueprint' files
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Type, get_type_hints

from attr import ib as attribute
from attr import s as ClassOfAttributes
from flask_restful import Resource

from restapi import decorators
from restapi.config import ABS_RESTAPI_PATH, CONF_PATH, CUSTOM_PACKAGE
from restapi.env import Env
from restapi.rest.annotations import inject_apispec_docs
from restapi.services.authentication import User
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
# Argument 2 to "__init__" becomes "Type[Any]" due to an unfollowed import
class EndpointElements:  # type: ignore
    # Type of variable becomes "Type[Any]" due to an unfollowed import
    cls: Type[Resource] = attribute(default=None)  # type: ignore
    uris: List[str] = attribute(default=[])
    # {'method': path, 'get': path, 'post': path}
    methods: Dict[str, str] = attribute(default={})
    tags: List[str] = attribute(default=[])
    private: bool = attribute(default=False)


class EndpointsLoader:
    def __init__(self) -> None:

        # Used by server.py to load endpoints definitions
        self.endpoints: List[EndpointElements] = []
        # Used by server.py to remove unmapped methods
        self.uri2methods: Dict[str, List[str]] = {}
        # Used by server.py to configure ApiSpec
        self.tags: List[Dict[str, str]] = []

        # Used by swagger specs endpoints to show authentication info
        self.authenticated_endpoints: Dict[str, Dict[str, bool]] = {}
        # Used by swagger spec endpoint to remove private endpoints from public requests
        self.private_endpoints: Dict[str, Dict[str, bool]] = {}

        self._used_tags: Set[str] = set()

    def load_configuration(self) -> Dict[str, Any]:
        # Reading configuration

        CONF_FOLDERS = Env.load_variables_group(prefix="project_confs")
        defaults_path = Path(CONF_FOLDERS.get("defaults_path", CONF_PATH))
        base_path = Path(CONF_FOLDERS.get("base_path", CONF_PATH))
        projects_path = Path(CONF_FOLDERS.get("projects_path", CONF_PATH))
        submodules_path = Path(CONF_FOLDERS.get("submodules_path", CONF_PATH))

        try:
            configuration, self._extended_project, _ = read_configuration(
                default_file_path=defaults_path,
                base_project_path=base_path,
                projects_path=projects_path,
                submodules_path=submodules_path,
            )
        except AttributeError as e:  # pragma: no cover
            print_and_exit(str(e))

        return configuration

    def load_endpoints(self) -> None:

        # core endpoints folder (rapydo/http-api)
        self.load_endpoints_folder(ABS_RESTAPI_PATH)

        # endpoints folder from extended project, if any
        if self._extended_project is not None:
            self.load_endpoints_folder(Path(self._extended_project))

        # custom endpoints folder
        self.load_endpoints_folder(Path(CUSTOM_PACKAGE))

        # Used in swagger specs endpoint
        self.tags = EndpointsLoader.remove_unused_tags(
            mem.configuration["tags"], self._used_tags
        )

        self.detect_endpoints_shadowing()

    @staticmethod
    def skip_endpoint(depends_on: List[str]) -> Tuple[bool, Optional[str]]:
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

    # Return type becomes "List[Type[Any]]" due to an unfollowed import
    def extract_endpoints(self, base_dir: Path) -> List[Type[Resource]]:  # type: ignore

        endpoints_classes = []
        # get last item of the path
        # normpath is required to strip final / if any
        base_module = base_dir.name

        apis_dir = base_dir.joinpath("endpoints")
        apiclass_module = f"{base_module}.endpoints"
        for epfile in apis_dir.glob("*.py"):

            # get module name (es: endpoints.filename)

            module_name = f"{apiclass_module}.{epfile.stem}"
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
                if (
                    not hasattr(epclss, "methods") or epclss.methods is None
                ):  # pragma: no cover
                    continue

                log.debug("Importing {} from {}", class_name, module_name)

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

    def load_endpoints_folder(self, base_dir: Path) -> None:
        # Walk folders looking for endpoints

        for epclss in self.extract_endpoints(base_dir):

            # Building endpoint
            endpoint = EndpointElements(
                uris=[],
                methods={},
                cls=epclss,
                tags=epclss.labels,
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

                if auth_required or auth_optional:
                    parameters = get_type_hints(fn)

                    if auth_required:
                        expected_annotation = User
                    else:
                        expected_annotation = Optional[User]

                    if (
                        "user" not in parameters
                        or parameters["user"] != expected_annotation
                    ):  # pragma: no cover

                        if "user" in parameters:
                            log.critical(
                                "Wrong user parameter in {}.{} (function {}), "
                                "expected {} but found {}",
                                epclss.__name__,
                                method_fn,
                                fn.__name__,
                                expected_annotation,
                                parameters["user"],
                            )
                        else:
                            log.critical(
                                "Missing user: {} parameter in {}.{} (function {})",
                                expected_annotation,
                                epclss.__name__,
                                method_fn,
                                fn.__name__,
                            )

                if not hasattr(fn, "uri"):  # pragma: no cover
                    print_and_exit(
                        "Invalid {} endpoint in {}: missing endpoint decorator",
                        method_fn,
                        epclss.__name__,
                    )

                endpoint.methods[method_fn] = fn.uri

                if fn.uri.startswith("/api/public/") or fn.uri.startswith(
                    "/api/app/"
                ):  # pragma: no cover
                    log.critical(
                        "Due to a BUG on the proxy configuration, "
                        "the {} URL will not work in production mode",
                        fn.uri,
                    )

                self.authenticated_endpoints.setdefault(fn.uri, {})
                # method_fn is equivalent to m.lower()
                self.authenticated_endpoints[fn.uri].setdefault(
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
                endpoint.uris.append(fn.uri)

                self.private_endpoints.setdefault(fn.uri, {})
                self.private_endpoints[fn.uri].setdefault(method_fn, endpoint.private)

                # Used by server.py to remove unmapped methods
                self.uri2methods.setdefault(fn.uri, [])
                self.uri2methods[fn.uri].append(method_fn)

                self._used_tags.update(endpoint.tags)
            self.endpoints.append(endpoint)

    @staticmethod
    def remove_unused_tags(
        all_tags: Dict[str, str], used_tags: Set[str]
    ) -> List[Dict[str, str]]:
        tags: List[Dict[str, str]] = []
        for tag, desc in all_tags.items():
            if tag not in used_tags:  # pragma: no cover
                log.debug("Skipping unsed tag: {}", tag)
                continue
            tags.append({"name": tag, "description": desc})
        return tags

    def detect_endpoints_shadowing(self) -> None:
        # Verify mapping duplication or shadowing
        # Example of shadowing:
        # /xyz/<variable>
        # /xyz/abc
        # The second endpoint is shadowed by the first one
        mappings: Dict[str, Set[str]] = {}
        # Type of variable becomes "Dict[str, Dict[str, Type[Any]]]"
        #   due to an unfollowed import
        classes: Dict[str, Dict[str, Type[Resource]]] = {}  # type: ignore
        # duplicates are found while filling the dictionaries
        for endpoint in self.endpoints:
            for method, uri in endpoint.methods.items():
                mappings.setdefault(method, set())
                classes.setdefault(method, {})

                if uri in mappings[method]:  # pragma: no cover
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
        for method, tmp_uris2 in mappings.items():
            for idx1, u1 in enumerate(tmp_uris2):
                for idx2, u2 in enumerate(tmp_uris2):
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
                    if not is_safe:  # pragma: no cover
                        log.warning(
                            "Endpoint shadowing detected: {}({m} {}) and {}({m} {})",
                            classes[method][u1].__name__,
                            u1,
                            classes[method][u2].__name__,
                            u2,
                            m=method.upper(),
                        )
