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

# https://mypy.readthedocs.io/en/latest/generics.html#generic-methods-and-generic-self
T = TypeVar("T", bound="Connector")

NO_AUTH = "NO_AUTHENTICATION"


# Also duplicated in Connector
class Service(TypedDict):
    module: Optional[ModuleType]
    available: bool
    variables: Dict[str, str]


class Detector:

    authentication_service: str = Env.get("AUTH_SERVICE") or NO_AUTH
    _authentication_module = None

    # Only used to get:
    # - services[name]['module']
    # - services[name]['available']
    # - services[name]['variables']

    # Also duplicated in Connector
    services: Dict[str, Service] = {
        "authentication": {
            "available": Env.get_bool("AUTH_ENABLE"),
            "module": None,
            "variables": {},
        }
    }

    # Deprecated since 1.0
    @staticmethod
    def check_availability(name: str) -> bool:
        log.warning(
            "Deprecated use of detector.check_availability, "
            "use Connector.check_availability instead"
        )
        if name not in Detector.services:
            return False

        return Detector.services[name].get("available", False)

    @staticmethod
    def get_authentication_instance():
        if not Detector._authentication_module:
            Detector._authentication_module = Meta.get_authentication_module(
                Detector.authentication_service
            )

        if Detector._authentication_module:
            return Detector._authentication_module.Authentication()
        # or Raise ServiceUnavailable ...
        return None

    @staticmethod
    def init():

        log.info("Authentication service: {}", Detector.authentication_service)

        services: Dict[str, Service] = {}

        services = Connector.load_connectors(
            ABS_RESTAPI_PATH, BACKEND_PACKAGE, services
        )

        if EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            services = Connector.load_connectors(
                os.path.join(os.curdir, EXTENDED_PACKAGE), EXTENDED_PACKAGE, services
            )

        services = Connector.load_connectors(
            os.path.join(os.curdir, CUSTOM_PACKAGE), CUSTOM_PACKAGE, services
        )

        Detector.services = services
        Connector.services = services

    @staticmethod
    def init_services(
        app: Flask,
        project_init: bool = False,
        project_clean: bool = False,
        worker_mode: bool = False,
        options: Optional[Dict[str, bool]] = None,
    ) -> None:

        Connector.app = app

        if options is None:
            options = {}

        for connector_name, service in Detector.services.items():

            if not service.get("available", False):
                continue

        if Detector.authentication_service == NO_AUTH:
            if not worker_mode:
                log.warning("No authentication service configured")
        elif Detector.authentication_service not in Detector.services:
            print_and_exit(
                "Auth service '{}' is unreachable", Detector.authentication_service
            )
        elif not Detector.services[Detector.authentication_service].get(
            "available", False
        ):
            print_and_exit(
                "Auth service '{}' is not available", Detector.authentication_service
            )

        if Detector.authentication_service != NO_AUTH:

            authentication_instance = Detector.get_authentication_instance()
            authentication_instance.module_initialization()

            # Only once in a lifetime
            if project_init:

                # Connector instance needed here
                connector = glom(
                    Detector.services, f"{Detector.authentication_service}.module"
                ).get_instance()
                log.debug("Initializing {}", Detector.authentication_service)
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
                    Detector.services, f"{Detector.authentication_service}.module"
                ).get_instance()
                log.debug("Destroying {}", Detector.authentication_service)
                connector.destroy()


detector = Detector

detector.init()
