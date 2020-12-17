import abc
import os
from datetime import datetime, timedelta
from types import ModuleType, TracebackType
from typing import Any, Dict, Optional, Tuple, Type, TypeVar

# mypy: ignore-errors
from flask import Flask
from flask import _app_ctx_stack as stack

from restapi.config import (
    ABS_RESTAPI_PATH,
    BACKEND_PACKAGE,
    CUSTOM_PACKAGE,
    EXTENDED_PACKAGE,
    EXTENDED_PROJECT_DISABLED,
)
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.services.authentication import BaseAuthentication
from restapi.utilities import print_and_exit
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

# https://mypy.readthedocs.io/en/latest/generics.html#generic-methods-and-generic-self
T = TypeVar("T", bound="Connector")

CONNECTORS_FOLDER = "connectors"
NO_AUTH = "NO_AUTHENTICATION"

# thread-id.ConnectorName.params-unique-key = instance
InstancesCache = Dict[int, Dict[str, Dict[str, T]]]
# service-name => dict of variables
Services = Dict[str, Dict[str, str]]


class Connector(metaclass=abc.ABCMeta):

    authentication_service: str = Env.get("AUTH_SERVICE") or NO_AUTH
    # Available services with associated env variables
    services: Services = {}

    # Assigned by init_app
    app: Flask = None

    # Used by get_authentication_module
    _authentication_module: Optional[ModuleType] = None

    # Returned by __getattr__ in neo4j, sqlalchemy and mongo connectors
    _models: Dict[str, Type] = {}

    # Used by set_object and get_object
    _instances: InstancesCache = {}

    def __init__(self) -> None:

        # This is the lower-cased class name (neomodel, celeryext)
        self.name = self.__class__.__name__.lower()
        # This is the folder name corresponding to the connector name (neo4j, celery, )
        # self.__class__.__module__ == restapi.connectors.sqlalchemy
        # .split(".") == ['restapi', 'connectors', 'sqlalchemy']
        # [-1] == 'sqlalchemy'
        self.name = self.__class__.__module__.split(".")[-1]

        # Will be modified by self.disconnect()
        self.disconnected = False

        # Added to convince mypy that self.app cannot be None
        if self.app is None:  # pragma: no cover
            # This should never happen because app is
            # assigned during init_services
            from flask import current_app

            self.app = current_app

    @staticmethod
    def init() -> None:

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

    def __exit__(
        self,
        exctype: Optional[Type[BaseException]],
        excinst: Optional[BaseException],
        exctb: Optional[TracebackType],
    ) -> bool:
        if not self.disconnected:
            self.disconnect()
            return True
        return False

    @abc.abstractmethod
    def get_connection_exception(
        self,
    ) -> Optional[Tuple[Type[BaseException]]]:  # pragma: no cover
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

    @property
    def variables(self) -> Dict[str, str]:
        return self.services.get(self.name) or {}

    @classmethod
    def load_connectors(cls, path: str, module: str, services: Services) -> Services:

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
                variables = Env.load_variables_group(prefix="alchemy")
            else:
                variables = Env.load_variables_group(prefix=connector)

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
                continue

            connector_module = Connector.get_module(connector, module)
            classes = Meta.get_new_classes_from_module(connector_module)
            for class_name, connector_class in classes.items():
                if not issubclass(connector_class, Connector):
                    continue

                break
            else:
                log.error("No connector class found in {}/{}", main_folder, connector)
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

            services[connector] = variables

            # NOTE: module loading algoritm is based on core connectors
            # if you need project connectors with models please review this part
            models_file = os.path.join(connector_path, "models.py")

            if os.path.isfile(models_file):
                log.debug("Loading models from {}", connector_path)

                base_models = Meta.import_models(
                    connector, BACKEND_PACKAGE, mandatory=True
                )
                if EXTENDED_PACKAGE == EXTENDED_PROJECT_DISABLED:
                    extended_models = {}
                else:
                    extended_models = Meta.import_models(connector, EXTENDED_PACKAGE)
                custom_models = Meta.import_models(connector, CUSTOM_PACKAGE)

                connector_class.set_models(base_models, extended_models, custom_models)

            log.debug("Got class definition for {}", connector_class)

        return services

    @staticmethod
    def get_module(connector: str, module: str) -> Optional[ModuleType]:
        return Meta.get_module_from_string(
            ".".join((module, CONNECTORS_FOLDER, connector))
        )

    @staticmethod
    def get_authentication_instance() -> BaseAuthentication:
        if not Connector._authentication_module:
            Connector._authentication_module = Connector.get_module(
                Connector.authentication_service, BACKEND_PACKAGE
            )

        if Connector._authentication_module:
            return Connector._authentication_module.Authentication()

        log.critical("{} not available", Connector.authentication_service)
        raise ServiceUnavailable("Authentication service not available")

    @staticmethod
    def init_app(app: Flask, worker_mode: bool = False) -> None:

        Connector.app = app

        if Connector.authentication_service == NO_AUTH:
            if not worker_mode:
                log.warning("No authentication service configured")
            return

        if Connector.authentication_service not in Connector.services:
            print_and_exit(
                "Auth service '{}' is not available", Connector.authentication_service
            )

        authentication_instance = Connector.get_authentication_instance()
        authentication_instance.module_initialization()

    @staticmethod
    def project_init(options: Optional[Dict[str, bool]] = None) -> None:

        if Connector.authentication_service != NO_AUTH:
            authentication_instance = Connector.get_authentication_instance()

            connector_module = Connector.get_module(
                Connector.authentication_service, BACKEND_PACKAGE
            )
            connector = connector_module.get_instance()

            log.debug("Initializing {}", Connector.authentication_service)
            connector.initialize()

            if options is None:
                options = {}

            with Connector.app.app_context():
                authentication_instance.init_auth_db(options)
                log.info("Initialized authentication module")

            if mem.initializer(app=Connector.app):
                log.info("Vanilla project has been initialized")
            else:
                log.error("Errors during custom initialization")

    @staticmethod
    def project_clean() -> None:
        if Connector.authentication_service != NO_AUTH:

            connector_module = Connector.get_module(
                Connector.authentication_service, BACKEND_PACKAGE
            )
            connector = connector_module.get_instance()

            log.debug("Destroying {}", Connector.authentication_service)
            connector.destroy()

    @classmethod
    def set_models(
        cls,
        base_models: Dict[str, Type],
        extended_models: Dict[str, Type],
        custom_models: Dict[str, Type],
    ) -> None:

        # Join models as described by issue #16
        cls._models = base_models
        for m in [extended_models, custom_models]:
            for key, model in m.items():

                # Verify if overriding
                if key in base_models.keys():
                    original_model = base_models[key]
                    # Override
                    if issubclass(model, original_model):
                        log.debug("Overriding model {}", key)
                        cls._models[key] = model
                        continue

                # Otherwise just append
                cls._models[key] = model

        if len(cls._models) > 0:
            log.debug("Models loaded")

    @staticmethod
    def is_external(host: str) -> bool:
        return not host.endswith(".dockerized.io")

    @classmethod
    def set_object(cls, name: str, obj: T, key: str = "[]") -> None:
        """ set object into internal array """

        tid = os.getpid()
        cls._instances.setdefault(tid, {})
        cls._instances[tid].setdefault(name, {})
        cls._instances[tid][name][key] = obj

    @classmethod
    def get_object(cls, name: str, key: str = "[]") -> Optional[T]:
        """ recover object if any """

        tid = os.getpid()
        cls._instances.setdefault(tid, {})
        cls._instances[tid].setdefault(name, {})
        return cls._instances[tid][name].get(key, None)

    @classmethod
    def disconnect_all(cls) -> None:
        for connectors in cls._instances.values():
            for instances in connectors.values():
                for instance in instances.values():
                    if not instance.disconnected:
                        log.info(
                            "Disconnecting {} {}", instance.name, hex(id(instance))
                        )
                        instance.disconnect()

        cls._instances.clear()

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
        return name in Connector.services

    def get_instance(
        self: T,
        verification: Optional[int] = None,
        expiration: Optional[int] = None,
        **kwargs,
    ) -> T:

        if not Connector.check_availability(self.name):
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
