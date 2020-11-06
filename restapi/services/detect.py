import os
from typing import Dict

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


class Detector:
    def __init__(self):

        self.authentication_service = Env.get("AUTH_SERVICE")

        log.info("Authentication service: {}", self.authentication_service)

        self.authentication_instance = None

        self.services: Dict[str, Dict[str, bool]] = {AUTH_NAME: {"available": Env.get_bool("AUTH_ENABLE")}}

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

    def get_service_instance(self, service_name, verify=False, **kwargs):
        if service_name == AUTH_NAME:
            return self.authentication_instance

        connector = self.get_connector(service_name)

        instance = connector.get_instance(verify=verify, **kwargs)

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

            self.services.setdefault(connector, {})
            self.services[connector]["available"] = enabled or external

            if not self.services[connector]["available"]:
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
                self.services[connector]["available"] = False
                continue

            self.services[connector]["variables"] = variables

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

            try:
                connector_instance = ConnectorClass(app)
            except TypeError as e:  # pragma: no cover
                print_and_exit("Your class {} is not compliant:\n{}", connector_name, e)

            self.services[connector_name]["connector"] = connector_instance

            try:
                instances[connector_name] = connector_instance.get_instance()
            except ServiceUnavailable:
                print_and_exit("Service unavailable: {}", connector_name)

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

                connector = self.services.get(self.authentication_service).get(
                    "connector"
                )
                log.debug("Initializing {}", self.authentication_service)
                connector.initialize()

                with app.app_context():
                    self.authentication_instance.init_auth_db(options)
                    log.info("Initialized authentication module")

                self.project_initialization(instances, app=app)

            if project_clean:
                connector = self.services.get(self.authentication_service).get(
                    "connector"
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

        if connector not in self.services:
            log.error("Connector {} not found", connector)
            return None

        if not self.services[connector].get("available", False):
            log.error("Connector {} is not available", connector)
            return None

        if "connector" not in self.services[connector]:
            c = self.services[connector].get("class")
            self.services[connector]["connector"] = c(app=None)

        return self.get_service_instance(connector)


detector = Detector()
