import os
from typing import Any, Dict, Optional, TypeVar, Union

from glom import glom

from restapi.config import (
    ABS_RESTAPI_PATH,
    BACKEND_PACKAGE,
    CUSTOM_PACKAGE,
    EXTENDED_PACKAGE,
    EXTENDED_PROJECT_DISABLED,
)
from restapi.connectors import Connector
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.utilities import print_and_exit
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

AUTH_NAME = "authentication"
CONNECTORS_FOLDER = "connectors"

# https://mypy.readthedocs.io/en/latest/generics.html#generic-methods-and-generic-self
T = TypeVar("T", bound="Connector")


class Detector:
    def __init__(self):

        self.authentication_service = Env.get("AUTH_SERVICE")

        log.info("Authentication service: {}", self.authentication_service)

        self.authentication_instance = None

        self.services: Dict[str, Dict[str, Any]] = {
            AUTH_NAME: {"available": Env.get_bool("AUTH_ENABLE")}
        }

        self.load_services(ABS_RESTAPI_PATH, BACKEND_PACKAGE)

        if EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            self.load_services(
                os.path.join(os.curdir, EXTENDED_PACKAGE), EXTENDED_PACKAGE
            )

        self.load_services(os.path.join(os.curdir, CUSTOM_PACKAGE), CUSTOM_PACKAGE)

    def get_connector(self, name):

        service = self.services.get(name)

        if service is None:
            raise ServiceUnavailable(f"Service {name} not found")

        if not service.get("available", False):
            raise ServiceUnavailable(f"Service {name} is not available")

        connector = service.get("connector")

        if connector is None:
            raise ServiceUnavailable(f"Connector {name} is not available")

        return connector

    def get_authentication_instance(self):
        return self.authentication_instance

    def get_service_instance(
        self: "Detector",
        service_name: str,
        verify: Optional[int] = None,
        expiration: Optional[int] = None,
        **kwargs: Union[Optional[str], int],
    ) -> Connector:

        # Deprecated since 0.9
        log.warning(
            "Deprecated use of detector.get_service_instance, "
            "use yourconnector.get_instace() instead"
        )
        connector: Connector = self.get_connector(service_name)

        instance: Connector = connector.get_instance(
            verify=verify, expiration=expiration, **kwargs
        )

        return instance

    def load_services(self, path, module):

        main_folder = os.path.join(path, CONNECTORS_FOLDER)
        if not os.path.isdir(main_folder):
            log.debug("Connectors folder not found: {}", main_folder)
            return False

        # Looking for all file in apis folder
        for connector in os.listdir(main_folder):
            connector_path = os.path.join(path, CONNECTORS_FOLDER, connector)
            if not os.path.isdir(connector_path):
                continue
            if connector.startswith("_"):
                continue

            # This is the only exception... we should rename sqlalchemy as alchemy
            if connector == "sqlalchemy":
                prefix = "alchemy"
            else:
                prefix = connector

            variables = Detector.load_variables(prefix=prefix)

            if not Env.to_bool(variables.get("enable_connector", True)):
                log.info("{} connector is disabled", connector)
                continue

            # Was this service enabled from the developer?
            if host := variables.get("host"):
                external = not host.endswith(".dockerized.io")
            else:
                variables["enabled"] = "0"
                external = False

            enabled = Env.to_bool(variables.get("enable"))
            available = enabled or external

            self.services.setdefault(connector, {})
            # To be removed
            self.services[connector]["available"] = available

            if not available:
                continue

            connector_module = Meta.get_module_from_string(
                ".".join((module, CONNECTORS_FOLDER, connector))
            )
            classes = Meta.get_new_classes_from_module(connector_module)
            for class_name, connector_class in classes.items():
                if not issubclass(connector_class, Connector):
                    continue

                break
            else:
                log.error("No connector class found in {}/{}", path, connector)
                # To be removed
                self.services[connector]["available"] = False
                continue

            try:
                # This is to test the Connector compliance,
                # i.e. to verify instance and get_isntance in the connector module
                connector_module.instance
                connector_module.get_instance
            except AttributeError as e:
                print_and_exit(e)

            self.services[connector]["variables"] = variables

            connector_class.available = True
            connector_class.set_variables(variables)

            # NOTE: module loading algoritm is based on core connectors
            # if you need project connectors with models please review this part
            models_file = os.path.join(connector_path, "models.py")

            if os.path.isfile(models_file):
                log.debug("Loading models from {}", connector_path)

                base_models = Meta.import_models(
                    connector, BACKEND_PACKAGE, exit_on_fail=True
                )
                if EXTENDED_PACKAGE == EXTENDED_PROJECT_DISABLED:
                    extended_models = {}
                else:
                    extended_models = Meta.import_models(
                        connector, EXTENDED_PACKAGE, exit_on_fail=False
                    )
                custom_models = Meta.import_models(
                    connector, CUSTOM_PACKAGE, exit_on_fail=False
                )

                connector_class.set_models(base_models, extended_models, custom_models)

            self.services[connector]["class"] = connector_class

            log.debug("Got class definition for {}", connector_class)

        return True

    @staticmethod
    def load_variables(prefix: str) -> Dict[str, str]:

        prefix += "_"

        variables: Dict[str, str] = {}

        for var, value in os.environ.items():

            var = var.lower()

            if not var.startswith(prefix):
                continue

            # Fix key and value before saving
            key = var[len(prefix) :]
            # One thing that we must avoid is any quote around our value
            value = value.strip('"').strip("'")
            # save
            variables[key] = value

        return variables

    def init_services(
        self,
        app,
        project_init=False,
        project_clean=False,
        worker_mode=False,
        options=None,
    ):

        Connector.app = app

        if options is None:
            options = {}

        instances = {}
        for connector_name, service in self.services.items():

            if not service.get("available", False):
                continue

            # Get connectors class and build the connector object
            ConnectorClass = service.get("class")

            if ConnectorClass is None:
                if connector_name != AUTH_NAME:  # pragma: no cover
                    print_and_exit(
                        "Connector misconfiguration {} {}", connector_name, service
                    )
                continue

            # ####### COULD BE REMOVED ??? ###########
            try:
                connector_instance = ConnectorClass()
            except TypeError as e:  # pragma: no cover
                print_and_exit("Your class {} is not compliant:\n{}", connector_name, e)

            # This should be no longer needed...
            self.services[connector_name]["connector"] = connector_instance

            try:
                instances[connector_name] = connector_instance.get_instance()
            except ServiceUnavailable:
                print_and_exit("Service unavailable: {}", connector_name)
            ##########################################

            # instances[connector_name] =
            #             get_instance
        if self.authentication_service is None:
            if not worker_mode:
                log.warning("No authentication service configured")
        elif self.authentication_service not in self.services:
            print_and_exit(
                "Auth service '{}' is unreachable", self.authentication_service
            )
        elif not self.services[self.authentication_service].get("available", False):
            print_and_exit(
                "Auth service '{}' is not available", self.authentication_service
            )

        if self.authentication_service is not None:
            auth_module = Meta.get_authentication_module(self.authentication_service)
            db = instances[self.authentication_service]
            self.authentication_instance = auth_module.Authentication(db)

            # Only once in a lifetime
            if project_init:

                connector = glom(
                    self.services, f"{self.authentication_service}.connector"
                )
                log.debug("Initializing {}", self.authentication_service)
                connector.initialize()

                with app.app_context():
                    self.authentication_instance.init_auth_db(options)
                    log.info("Initialized authentication module")

                self.project_initialization(instances, app=app)

            if project_clean:
                connector = glom(
                    self.services, f"{self.authentication_service}.connector"
                )
                log.debug("Destroying {}", self.authentication_service)
                connector.destroy()

    def check_availability(self, name):
        return glom(self.services, f"{name}.available", default=False)

    @classmethod
    def project_initialization(self, instances, app=None):

        if mem.initializer(services=instances, app=app):
            log.info("Vanilla project has been initialized")
        else:
            log.error("Errors during custom initialization")

    def get_debug_instance(self, connector):

        # Deprecated since 0.9
        log.warning(
            "Deprecated use of get_debug_instance, create a normal instance instead"
        )

        if connector not in self.services:
            log.error("Connector {} not found", connector)
            return None

        if not self.services[connector].get("available", False):
            log.error("Connector {} is not available", connector)
            return None

        if "connector" not in self.services[connector]:
            c = glom(self.services[connector], "class")
            self.services[connector]["connector"] = c(app=None)

        return self.get_service_instance(connector)


detector = Detector()
