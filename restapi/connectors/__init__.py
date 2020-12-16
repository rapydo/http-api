import abc
import os
from datetime import datetime, timedelta
from types import ModuleType
from typing import Any, Dict, Optional, TypedDict, TypeVar

# mypy: ignore-errors
from flask import Flask
from flask import _app_ctx_stack as stack
from glom import glom

from restapi.config import (
    ABS_RESTAPI_PATH,
    BACKEND_PACKAGE,
    CUSTOM_PACKAGE,
    EXTENDED_PACKAGE,
    EXTENDED_PROJECT_DISABLED,
)
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.utilities import print_and_exit
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

# https://mypy.readthedocs.io/en/latest/generics.html#generic-methods-and-generic-self
T = TypeVar("T", bound="Connector")

CONNECTORS_FOLDER = "connectors"
NO_AUTH = "NO_AUTHENTICATION"

InstancesCache = Dict[int, Dict[str, Dict[str, T]]]


class Service(TypedDict):
    module: Optional[ModuleType]
    available: bool
    variables: Dict[str, str]


class Connector(metaclass=abc.ABCMeta):

    authentication_service: str = Env.get("AUTH_SERVICE") or NO_AUTH
    variables: Dict[str, str] = {}
    models: Dict[str, Any] = {}
    # Assigned by init_services
    app: Flask = None

    # Modified by during init_services
    available: bool = False

    services: Dict[str, Service] = {
        "authentication": {
            "available": Env.get_bool("AUTH_ENABLE"),
            "module": None,
            "variables": {},
        }
    }

    # will contain:
    # instances = {
    #     'thread-id': {
    #         'ConnectorName': {
    #             'params-unique-key': instance
    #         }
    #     }
    # }
    instances: InstancesCache = {}

    # App can be removed?
    def __init__(self, app=None):

        self.name = self.__class__.__name__.lower()

        # Will be modified by self.disconnect()
        self.disconnected = False

        # Added to convince mypy that self.app cannot be None
        if self.app is None:  # pragma: no cover
            # This should never happen because app is
            # assigned during init_services
            from flask import current_app

            self.app = current_app

    @staticmethod
    def init():

        log.info("Authentication service: {}", Connector.authentication_service)

        Connector.services = Connector.load_connectors(
            ABS_RESTAPI_PATH, BACKEND_PACKAGE, Connector.services
        )

        if EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            Connector.services = Connector.load_connectors(
                os.path.join(os.curdir, EXTENDED_PACKAGE),
                EXTENDED_PACKAGE,
                Connector.services,
            )

        Connector.services = Connector.load_connectors(
            os.path.join(os.curdir, CUSTOM_PACKAGE), CUSTOM_PACKAGE, Connector.services
        )

    def __del__(self) -> None:
        if not self.disconnected:
            self.disconnect()

    def __enter__(self: T) -> T:
        return self

    def __exit__(self, _type, value, tb):
        if not self.disconnected:
            self.disconnect()

    @abc.abstractmethod
    def get_connection_exception(self):  # pragma: no cover
        return None

    @abc.abstractmethod
    def connect(self, **kwargs) -> None:  # pragma: no cover
        return

    @abc.abstractmethod
    def disconnect(self) -> None:  # pragma: no cover
        return

    @abc.abstractmethod
    def is_connected(instance: T) -> bool:  # pragma: no cover
        return True

    def destroy(self) -> None:  # pragma: no cover
        print_and_exit("Missing destroy method in {}", self.__class__.__name__)

    def initialize(self) -> None:  # pragma: no cover
        print_and_exit("Missing initialize method in {}", self.__class__.__name__)

    @classmethod
    def load_connectors(
        cls, path: str, module: str, services: Dict[str, Service]
    ) -> Dict[str, Service]:

        main_folder = os.path.join(path, CONNECTORS_FOLDER)
        if not os.path.isdir(main_folder):
            log.debug("Connectors folder not found: {}", main_folder)
            return services

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
                    external = cls.is_external(host)
                else:
                    variables["enable"] = "0"

            enabled = Env.to_bool(variables.get("enable"))
            available = enabled or external

            if not available:
                services[connector] = {
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
                services[connector]["available"] = False
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

            services[connector] = {
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

        return services

    @staticmethod
    def init_services(
        app: Flask,
        project_init: bool = False,
        project_clean: bool = False,
        worker_mode: bool = False,
        options: Optional[Dict[str, bool]] = None,
        Detector: Any = None,
    ) -> None:

        Connector.app = app

        if options is None:
            options = {}

        for connector_name, service in Connector.services.items():

            if not service.get("available", False):
                continue

        if Connector.authentication_service == NO_AUTH:
            if not worker_mode:
                log.warning("No authentication service configured")
        elif Connector.authentication_service not in Connector.services:
            print_and_exit(
                "Auth service '{}' is unreachable", Connector.authentication_service
            )
        elif not Connector.services[Connector.authentication_service].get(
            "available", False
        ):
            print_and_exit(
                "Auth service '{}' is not available", Connector.authentication_service
            )

        if Connector.authentication_service != NO_AUTH:

            authentication_instance = Detector.get_authentication_instance()
            authentication_instance.module_initialization()

            # Only once in a lifetime
            if project_init:

                # Connector instance needed here
                connector = glom(
                    Connector.services, f"{Connector.authentication_service}.module"
                ).get_instance()
                log.debug("Initializing {}", Connector.authentication_service)
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
                    Connector.services, f"{Connector.authentication_service}.module"
                ).get_instance()
                log.debug("Destroying {}", Connector.authentication_service)
                connector.destroy()

    @classmethod
    def set_models(cls, base_models, extended_models, custom_models):

        # Join models as described by issue #16
        cls.models = base_models
        for m in [extended_models, custom_models]:
            for key, model in m.items():

                # Verify if overriding
                if key in base_models.keys():
                    original_model = base_models[key]
                    # Override
                    if issubclass(model, original_model):
                        log.debug("Overriding model {}", key)
                        cls.models[key] = model
                        continue

                # Otherwise just append
                cls.models[key] = model

        if len(cls.models) > 0:
            log.debug("Models loaded")

    @classmethod
    def set_variables(cls, envvars: Dict[str, str]) -> None:
        cls.variables = envvars

    @staticmethod
    def is_external(host: str) -> bool:
        return not host.endswith(".dockerized.io")

    @classmethod
    def set_object(cls, name: str, obj: T, key: str = "[]") -> None:
        """ set object into internal array """

        tid = os.getpid()
        cls.instances.setdefault(tid, {})
        cls.instances[tid].setdefault(name, {})
        cls.instances[tid][name][key] = obj

    @classmethod
    def get_object(cls, name: str, key: str = "[]") -> Optional[T]:
        """ recover object if any """

        tid = os.getpid()
        cls.instances.setdefault(tid, {})
        cls.instances[tid].setdefault(name, {})
        return cls.instances[tid][name].get(key, None)

    @classmethod
    def disconnect_all(cls) -> None:
        for connectors in cls.instances.values():
            for instances in connectors.values():
                for instance in instances.values():
                    if not instance.disconnected:
                        log.info(
                            "Disconnecting {} {}", instance.name, hex(id(instance))
                        )
                        instance.disconnect()

        cls.instances.clear()

        log.info("[{}] All connectors disconnected", os.getpid())

    def initialize_connection(
        self, expiration: int, verification: int, **kwargs: Any
    ) -> T:

        # Create a new instance of itself
        obj = self.__class__()

        exceptions = obj.get_connection_exception()
        if exceptions is None:
            exceptions = (BaseException,)

        try:
            obj = obj.connect(**kwargs)
        except exceptions as e:
            log.error("{} raised {}: {}", obj.name, e.__class__.__name__, e)
            raise ServiceUnavailable({"Service Unavailable": "Internal server error"})

        obj.connection_time = datetime.now()

        if verification == 0:
            ver = None
        else:
            ver = obj.connection_time + timedelta(seconds=verification)
        obj.connection_verification_time = ver

        if expiration == 0:
            exp = None
        else:
            exp = obj.connection_time + timedelta(seconds=expiration)
        obj.connection_expiration_time = exp

        return obj

    @staticmethod
    def check_availability(name: str) -> bool:
        if name not in Connector.services:
            return False

        return Connector.services[name].get("available", False)

    def get_instance(
        self: T,
        verification: Optional[int] = None,
        expiration: Optional[int] = None,
        **kwargs,
    ) -> T:

        if not self.available:
            raise ServiceUnavailable(f"Service {self.name} is not available")

        if verification is None:
            # this should be the default value for this connector
            verification = Env.to_int(self.variables.get("verification_time"))

        if expiration is None:
            # this should be the default value for this connector
            expiration = Env.to_int(self.variables.get("expiration_time"))

        # When context is empty this is a connection at loading time
        # Do not save it
        if stack.top is None:
            log.debug("First connection for {}", self.name)
            # can raise ServiceUnavailable exception
            obj = self.initialize_connection(expiration, verification, **kwargs)
            return obj

        unique_hash = str(sorted(kwargs.items()))

        obj = self.get_object(name=self.name, key=unique_hash)

        # if an expiration time is set, verify the instance age
        if obj and obj.connection_expiration_time:

            # the instance is invalidated if older than the expiration time
            if datetime.now() >= obj.connection_expiration_time:

                log.info("{} connection is expired", self.name)
                obj.disconnect()
                obj = None

        # If a verification time is set, verify the instance age
        if obj and obj.connection_verification_time:
            now = datetime.now()

            # the instance is verified if older than the verification time
            if now >= obj.connection_verification_time:
                # if the connection is still valid, set a new verification time
                if obj.is_connected():
                    # Set the new verification time
                    ver = timedelta(seconds=verification)
                    obj.connection_verification_time = now + ver
                # if the connection is no longer valid, invalidate the instance
                else:
                    log.warning(
                        "{} is no longer connected, connector invalidated", self.name
                    )
                    obj.disconnected = True

        # return the instance only if still connected
        # (and not invalidated by the verification check)
        if obj and not obj.disconnected:
            return obj

        # can raise ServiceUnavailable exception
        obj = self.initialize_connection(expiration, verification, **kwargs)
        self.set_object(name=self.name, obj=obj, key=unique_hash)
        return obj


Connector.init()
