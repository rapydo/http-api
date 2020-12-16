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

    # Deprecated since 1.0
    @staticmethod
    def init():

        log.warning("Deprecated use of Detector.init(), it is no longer needed")

        log.info("Authentication service: {}", Detector.authentication_service)

        Detector.services = Connector.load_connectors(
            ABS_RESTAPI_PATH, BACKEND_PACKAGE, Detector.services
        )

        if EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            Detector.services = Connector.load_connectors(
                os.path.join(os.curdir, EXTENDED_PACKAGE),
                EXTENDED_PACKAGE,
                Detector.services,
            )

        Detector.services = Connector.load_connectors(
            os.path.join(os.curdir, CUSTOM_PACKAGE), CUSTOM_PACKAGE, Detector.services
        )

    # Deprecated since 1.0
    @staticmethod
    def init_services(
        app: Flask,
        project_init: bool = False,
        project_clean: bool = False,
        worker_mode: bool = False,
        options: Optional[Dict[str, bool]] = None,
    ) -> None:
        log.warning(
            "Deprecated use of Detector.init_services, "
            "use Connector.init_services instead"
        )

        return Connector.init_services(
            app=app,
            project_init=project_init,
            project_clean=project_clean,
            worker_mode=worker_mode,
            options=options,
            Detector=Detector,
        )


detector = Detector

detector.init()
