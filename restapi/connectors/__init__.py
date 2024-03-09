"""
Set of modules for the connection and handling of external services
"""

import abc
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from types import ModuleType, TracebackType
from typing import Any, Optional, TypeVar, cast

from flask import Flask

from restapi.config import (
    ABS_RESTAPI_PATH,
    BACKEND_PACKAGE,
    CUSTOM_PACKAGE,
    EXTENDED_PACKAGE,
    EXTENDED_PROJECT_DISABLED,
    TESTING,
)
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.services.authentication import BaseAuthentication, NoAuthentication
from restapi.tests_initialization import initialize_testing_environment
from restapi.utilities import print_and_exit
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

# https://mypy.readthedocs.io/en/latest/generics.html#generic-methods-and-generic-self
T = TypeVar("T", bound="Connector")

CONNECTORS_FOLDER = "connectors"
NO_AUTH = "NO_AUTHENTICATION"
DEFAULT_DATETIME = datetime.fromtimestamp(0)

# service-name => dict of variables
Services = dict[str, dict[str, str]]

ExceptionsList = Optional[tuple[type[Exception]]]


class Connector(metaclass=abc.ABCMeta):
    authentication_service: str = Env.get("AUTH_SERVICE", NO_AUTH)
    # Available services with associated env variables
    services: Services = {}

    # Assigned by init_app
    app: Optional[Flask] = None

    # Used by get_authentication_module
    _authentication_module: Optional[ModuleType] = None

    # Returned by __getattr__ in neo4j and sqlalchemy connectors
    _models: dict[str, type[Any]] = {}

    # Used by set_object and get_object
    _instances: dict[str, T] = {}  # type: ignore

    def __init__(self) -> None:
        # This is the lower-cased class name (neomodel, celeryext)
        # self.name = self.__class__.__name__.lower()
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

        self.connection_verification_time: Optional[datetime] = None
        self.connection_expiration_time: Optional[datetime] = None
        self.connection_time: datetime = DEFAULT_DATETIME

    @staticmethod
    def init() -> None:
        if Connector.authentication_service == NO_AUTH:
            log.info("No Authentication service configured")
        else:
            log.debug("Authentication service: {}", Connector.authentication_service)

        Connector.services = Connector.load_connectors(
            ABS_RESTAPI_PATH, BACKEND_PACKAGE, Connector.services
        )

        if EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            Connector.services = Connector.load_connectors(
                Path(EXTENDED_PACKAGE),
                EXTENDED_PACKAGE,
                Connector.services,
            )

        Connector.services = Connector.load_connectors(
            Path(CUSTOM_PACKAGE), CUSTOM_PACKAGE, Connector.services
        )

    def __del__(self) -> None:
        if not self.disconnected:
            self.disconnect()

    def __enter__(self: T) -> T:
        return self

    def __exit__(
        self,
        exctype: Optional[type[Exception]],
        excinst: Optional[Exception],
        exctb: Optional[TracebackType],
    ) -> bool:
        if not self.disconnected:
            self.disconnect()
        if excinst:  # pragma: no cover
            raise excinst
        return True

    @staticmethod
    @abc.abstractmethod
    def get_connection_exception() -> ExceptionsList:  # pragma: no cover
        return None

    @abc.abstractmethod
    def connect(self: T, **kwargs: Any) -> T:  # pragma: no cover
        return self

    @abc.abstractmethod
    def disconnect(self) -> None:  # pragma: no cover
        return

    @abc.abstractmethod
    def is_connected(self) -> bool:  # pragma: no cover
        return True

    def destroy(self) -> None:  # pragma: no cover
        print_and_exit("Missing destroy method in {}", self.__class__.__name__)

    def initialize(self) -> None:  # pragma: no cover
        print_and_exit("Missing initialize method in {}", self.__class__.__name__)

    @property
    def variables(self) -> dict[str, str]:
        return self.services.get(self.name) or {}

    @classmethod
    def load_connectors(cls, path: Path, module: str, services: Services) -> Services:
        main_folder = path.joinpath(CONNECTORS_FOLDER)
        if not main_folder.is_dir():
            log.debug("Connectors folder not found: {}", main_folder)
            return services

        for connector in main_folder.iterdir():
            if not connector.is_dir():
                continue

            connector_name = connector.name
            if connector_name.startswith("_"):
                continue

            # This is the only exception... we should rename sqlalchemy as alchemy
            if connector_name == "sqlalchemy":
                variables = Env.load_variables_group(prefix="alchemy")
            else:
                variables = Env.load_variables_group(prefix=connector_name)

            if not Env.to_bool(
                variables.get("enable_connector", True)
            ):  # pragma: no cover
                log.debug("{} connector is disabled", connector_name)
                continue

            external = False
            if "host" in variables:
                if host := variables.get("host"):
                    external = cls.is_external(host)
                # HOST found in variables but empty... never happens during tests
                else:  # pragma: no cover
                    variables["enable"] = "0"

            enabled = Env.to_bool(variables.get("enable"))

            # Celery is always enabled, if connector is enabled
            # No further check is needed on host/external
            available = enabled or external or connector_name == "celery"

            if not available:
                continue

            connector_module = Connector.get_module(connector_name, module)
            connector_class = Connector.get_class(connector_module)

            # Can't test connector misconfigurations...
            if not connector_module:  # pragma: no cover
                log.error("No connector module found in {}", connector)
                continue
            if not connector_class:  # pragma: no cover
                log.error("No connector class found in {}", connector)
                continue

            try:
                # This is to test the Connector compliance,
                # i.e. to verify instance and get_instance in the connector module
                # and verify that the Connector can be instanced
                connector_module.instance
                connector_module.get_instance
                connector_class()
            except AttributeError as e:  # pragma: no cover
                print_and_exit(str(e))

            services[connector_name] = variables

            log.debug("Got class definition for {}", connector_class)

        return services

    @staticmethod
    def get_module(connector: str, module: str) -> Optional[ModuleType]:
        return Meta.get_module_from_string(
            ".".join((module, CONNECTORS_FOLDER, connector))
        )

    @staticmethod
    def get_class(connector_module: Optional[ModuleType]) -> Optional[type[Any]]:
        if not connector_module:  # pragma: no cover
            return None

        classes = Meta.get_new_classes_from_module(connector_module)
        for connector_class in classes.values():
            if issubclass(connector_class, Connector):
                return connector_class

        return None  # pragma: no cover

    @staticmethod
    def get_authentication_instance() -> BaseAuthentication:
        if Connector.authentication_service == NO_AUTH:
            return NoAuthentication()

        if not Connector._authentication_module:
            Connector._authentication_module = Connector.get_module(
                Connector.authentication_service, BACKEND_PACKAGE
            )

        if not Connector._authentication_module:  # pragma: no cover
            log.critical("{} not available", Connector.authentication_service)
            raise ServiceUnavailable("Authentication service not available")

        return cast(
            BaseAuthentication, Connector._authentication_module.Authentication()
        )

    @staticmethod
    def init_app(app: Flask, worker_mode: bool = False) -> None:
        Connector.app = app

        if Connector.authentication_service == NO_AUTH:
            return

        if (
            Connector.authentication_service not in Connector.services
        ):  # pragma: no cover
            print_and_exit(
                "Auth service '{}' is not available", Connector.authentication_service
            )

        authentication_instance = Connector.get_authentication_instance()
        authentication_instance.module_initialization()

    @staticmethod
    def project_init(options: dict[str, bool]) -> None:
        if Connector.authentication_service != NO_AUTH:
            authentication_instance = Connector.get_authentication_instance()

            connector_module = Connector.get_module(
                Connector.authentication_service, BACKEND_PACKAGE
            )
            if not connector_module:  # pragma: no cover
                return None

            connector = connector_module.get_instance()

            log.debug("Initializing {}", Connector.authentication_service)
            connector.initialize()

            if not Connector.app:  # pragma: no cover
                log.error("Connector.app found uninitilizated at runtime")
                return None

            with Connector.app.app_context():
                authentication_instance.init_auth_db(options)
                log.info("Initialized authentication module")

            initializer = mem.initializer()
            if initializer:
                log.info("Vanilla project has been initialized")
            else:  # pragma: no cover
                log.error("Errors during custom initialization")

            if TESTING:
                # Core test initialization
                initialize_testing_environment(authentication_instance)
                # Custom test initialization
                initializer.initialize_testing_environment()

    @staticmethod
    def project_clean() -> None:
        if Connector.authentication_service != NO_AUTH:
            connector_module = Connector.get_module(
                Connector.authentication_service, BACKEND_PACKAGE
            )
            if not connector_module:  # pragma: no cover
                return None

            connector = connector_module.get_instance()

            log.debug("Destroying {}", Connector.authentication_service)
            connector.destroy()

    def load_models(self) -> None:
        base_models = Meta.import_models(self.name, BACKEND_PACKAGE, mandatory=True)
        if EXTENDED_PACKAGE == EXTENDED_PROJECT_DISABLED:
            extended_models = {}
        else:
            extended_models = Meta.import_models(self.name, EXTENDED_PACKAGE)
        custom_models = Meta.import_models(self.name, CUSTOM_PACKAGE)

        log.debug(
            "Models loaded from {}: core {}, extended {}, custom {}",
            self.name,
            len(base_models),
            len(extended_models),
            len(custom_models),
        )
        self.set_models(base_models, extended_models, custom_models)

    @classmethod
    def set_models(
        cls,
        base_models: dict[str, type[Any]],
        extended_models: dict[str, type[Any]],
        custom_models: dict[str, type[Any]],
    ) -> None:
        # Join models as described by issue #16
        cls._models = base_models
        for m in [extended_models, custom_models]:
            for key, model in m.items():
                # Verify if overriding => replace
                if key in base_models.keys():
                    if issubclass(model, base_models[key]):  # pragma: no cover
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
    def get_instance_cache_key(cls, name: str, key: str) -> str:
        tid = os.getpid()
        return f"{tid}:{name}:{key}"

    @classmethod
    def set_object(cls, name: str, key: str, obj: T) -> None:
        """set object into internal array"""
        cache_key = cls.get_instance_cache_key(name, key)
        cls._instances[cache_key] = obj

    @classmethod
    def get_object(cls, name: str, key: str) -> Optional["Connector"]:
        """recover object if any"""
        cache_key = cls.get_instance_cache_key(name, key)
        return cast(Optional["Connector"], cls._instances.get(cache_key))

    # From server.teardown... not executed during tests
    @classmethod
    def disconnect_all(cls) -> None:  # pragma: no cover
        for instance in cls._instances.values():
            if not instance.disconnected:  # type: ignore
                log.info(
                    "Disconnecting {} {}",
                    instance.name,  # type: ignore
                    hex(id(instance)),
                )
                instance.disconnect()  # type: ignore

        cls._instances.clear()

        log.info("[{}] All connectors disconnected", os.getpid())

    def initialize_connection(
        self: T, expiration: int, verification: int, **kwargs: str
    ) -> T:
        # Create a new instance of itself
        obj = self.__class__()

        exceptions = obj.get_connection_exception()
        if exceptions is None:
            exceptions = (Exception,)

        try:
            obj = obj.connect(**kwargs)
        except exceptions as e:
            log.error("{} raised {}: {}", obj.name, e.__class__.__name__, e)
            raise ServiceUnavailable(f"Service {self.name} is not available") from e

        obj.connection_time = datetime.now()

        obj.connection_verification_time = None
        if verification > 0:
            ver = obj.connection_time + timedelta(seconds=verification)
            obj.connection_verification_time = ver

        obj.connection_expiration_time = None
        if expiration > 0:
            exp = obj.connection_time + timedelta(seconds=expiration)
            obj.connection_expiration_time = exp

        return obj

    @staticmethod
    def check_availability(name: str) -> bool:
        if name == "authentication":
            return Connector.authentication_service != NO_AUTH

        return name in Connector.services

    def get_instance(
        self: T,
        verification: Optional[int] = None,
        expiration: Optional[int] = None,
        retries: int = 1,
        retry_wait: int = 0,
        **kwargs: str,
    ) -> T:
        if retries < 1:
            raise ServiceUnavailable(f"Invalid retry value: {retries}")

        if retry_wait < 0:
            raise ServiceUnavailable(f"Invalid retry wait value: {retry_wait}")

        if not Connector.check_availability(self.name):
            raise ServiceUnavailable(f"Service {self.name} is not available")

        if verification is None:
            # this should be the default value for this connector
            verification = Env.to_int(self.variables.get("verification_time"))

        if expiration is None:
            # this should be the default value for this connector
            expiration = Env.to_int(self.variables.get("expiration_time"))

        # This is a connection at loading time, do not save it
        if not mem.boot_completed:
            log.debug("First connection for {}", self.name)
            # can raise ServiceUnavailable exception
            return self.initialize_connection(expiration, verification, **kwargs)

        unique_hash = str(sorted(kwargs.items()))

        cached_obj = self.get_object(name=self.name, key=unique_hash)

        # if an expiration time is set, verify the instance age
        if cached_obj and cached_obj.connection_expiration_time:
            # the instance is invalidated if older than the expiration time
            if datetime.now() >= cached_obj.connection_expiration_time:
                log.info("{} connection is expired", self.name)
                cached_obj.disconnect()
                cached_obj = None

        # If a verification time is set, verify the instance age
        if cached_obj and cached_obj.connection_verification_time:
            now = datetime.now()

            # the instance is verified if older than the verification time
            if now >= cached_obj.connection_verification_time:
                # if the connection is still valid, set a new verification time
                if cached_obj.is_connected():
                    # Set the new verification time
                    ver = timedelta(seconds=verification)
                    cached_obj.connection_verification_time = now + ver
                # if the connection is no longer valid, invalidate the instance
                else:  # pragma: no cover
                    log.info(
                        "{} is no longer connected, connector invalidated", self.name
                    )
                    cached_obj.disconnected = True

        # return the instance only if still connected
        # (and not invalidated by the verification check)
        if cached_obj and not cached_obj.disconnected:
            return cast(T, cached_obj)

        # can raise ServiceUnavailable exception
        for retry in range(retries):
            try:
                instance = self.initialize_connection(
                    expiration, verification, **kwargs
                )
                break
            except ServiceUnavailable as e:
                # This is the last iteration:
                if retry == retries - 1:
                    raise e
                time.sleep(retry_wait)

        self.set_object(name=self.name, key=unique_hash, obj=instance)
        return instance


Connector.init()
