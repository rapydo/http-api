import os
from types import ModuleType
from typing import Dict, Optional, TypedDict, TypeVar

from flask import Flask
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
from restapi.utilities import print_and_exit
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

CONNECTORS_FOLDER = "connectors"

# https://mypy.readthedocs.io/en/latest/generics.html#generic-methods-and-generic-self
T = TypeVar("T", bound="Connector")


class Service(TypedDict):
    module: Optional[ModuleType]
    available: bool
    variables: Dict[str, str]


class Detector:
    def __init__(self):

        self.authentication_service = Env.get("AUTH_SERVICE")

        log.info("Authentication service: {}", self.authentication_service)

        # Only used to get:
        # - services[name]['module']
        # - services[name]['available']
        # - services[name]['variables']
        self.services: Dict[str, Service] = {
            "authentication": {
                "available": Env.get_bool("AUTH_ENABLE"),
                "module": None,
                "variables": {},
            }
        }

        self.load_services(ABS_RESTAPI_PATH, BACKEND_PACKAGE)

        if EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            self.load_services(
                os.path.join(os.curdir, EXTENDED_PACKAGE), EXTENDED_PACKAGE
            )

        self.load_services(os.path.join(os.curdir, CUSTOM_PACKAGE), CUSTOM_PACKAGE)

    def check_availability(self, name: str) -> bool:
        if name not in self.services:
            return False

        return self.services[name].get("available", False)

    def get_authentication_instance(self):
        return self.authentication_module.Authentication()

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

            variables = Env.load_variables_group(prefix=prefix)

            if not Env.to_bool(variables.get("enable_connector", True)):
                log.info("{} connector is disabled", connector)
                continue

            # if host is not in variables (like for Celery) do not consider it
            external = False
            if "host" in variables:
                if host := variables.get("host"):
                    external = Connector.is_external(host)
                else:
                    variables["enable"] = "0"

            enabled = Env.to_bool(variables.get("enable"))
            available = enabled or external

            if not available:
                self.services[connector] = {
                    "available": available,
                    "module": None,
                    "variables": {},
                }
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
                log.error("No connector class found in {}/{}", main_folder, connector)
                # To be removed
                self.services[connector]["available"] = False
                continue

            try:
                # This is to test the Connector compliance,
                # i.e. to verify instance and get_instance in the connector module
                # and verify that the Connector can be instanced
                connector_module.instance
                connector_module.get_instance
                connector_class()
            except AttributeError as e:  # pragma: no cover
                print_and_exit(e)

            self.services[connector] = {
                "available": available,
                "module": connector_module,
                "variables": variables,
            }

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

            log.debug("Got class definition for {}", connector_class)

        return True

    def init_services(
        self,
        app: Flask,
        project_init: bool = False,
        project_clean: bool = False,
        worker_mode: bool = False,
        options: Optional[Dict[str, bool]] = None,
    ) -> None:

        Connector.app = app

        if options is None:
            options = {}

        for connector_name, service in self.services.items():

            if not service.get("available", False):
                continue

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
            self.authentication_module = Meta.get_authentication_module(
                self.authentication_service
            )

            authentication_instance = self.authentication_module.Authentication()
            authentication_instance.module_initialization()

            # Only once in a lifetime
            if project_init:

                # Connector instance needed here
                connector = glom(
                    self.services, f"{self.authentication_service}.module"
                ).get_instance()
                log.debug("Initializing {}", self.authentication_service)
                connector.initialize()

                with app.app_context():
                    authentication_instance.init_auth_db(options)
                    log.info("Initialized authentication module")

                if mem.initializer(app=app):
                    log.info("Vanilla project has been initialized")
                else:
                    log.error("Errors during custom initialization")

            if project_clean:
                connector = glom(
                    self.services, f"{self.authentication_service}.module"
                ).get_instance()
                log.debug("Destroying {}", self.authentication_service)
                connector.destroy()


detector = Detector()
