import abc
import os
from datetime import datetime, timedelta
from typing import Dict, Optional, TypeVar

# mypy: ignore-errors
from flask import _app_ctx_stack as stack

from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.utilities import print_and_exit
from restapi.utilities.logs import log

# https://mypy.readthedocs.io/en/latest/generics.html#generic-methods-and-generic-self
T = TypeVar("T", bound="Connector")


class Connector(metaclass=abc.ABCMeta):

    variables: Dict[str, str] = {}
    models = {}
    # Assigned by Detector during init_services
    app = None

    # Modified by Detector during init_services
    available: bool = False

    # will contain:
    # objs = {
    #     'thread-id': {
    #         'ConnectorName': {
    #             'params-unique-key': instance
    #         }
    #     }
    # }
    objs = {}

    def __init__(self, app=None):

        self.name = self.__class__.__name__.lower()

        # Added to convince mypy that sel.app cannot be None
        if self.app is None:  # pragma: no cover
            # This should never happen because app is
            # assigned by Detector during init_services
            from flask import current_app

            self.app = current_app

        if app:
            # Deprecated since 0.9
            log.warning("Deprecated app parameter in {} initialization", self.name)

        # Will be modified by self.disconnect()
        self.disconnected = False

    def __enter__(self):
        return self

    def __exit__(self, _type, value, tb):
        self.disconnect()

    @abc.abstractmethod
    def get_connection_exception(self):  # pragma: no cover
        return None

    @abc.abstractmethod
    def connect(self, **kwargs):  # pragma: no cover
        return

    @abc.abstractmethod
    def disconnect(self):  # pragma: no cover
        return

    @abc.abstractmethod
    def is_connected(instance):  # pragma: no cover
        return True

    def destroy(self):  # pragma: no cover
        print_and_exit("Missing destroy method in {}", self.__class__.__name__)

    def initialize(self):  # pragma: no cover
        print_and_exit("Missing initialize method in {}", self.__class__.__name__)

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
    def set_variables(cls, envvars):
        cls.variables = envvars

    def set_object(self, obj, key="[]") -> None:
        """ set object into internal array """

        tid = os.getpid()
        self.objs.setdefault(tid, {})
        self.objs[tid].setdefault(self.name, {})
        self.objs[tid][self.name][key] = obj

    @staticmethod
    def is_external(host: str) -> bool:
        return not host.endswith(".dockerized.io")

    def get_object(self, key="[]"):
        """ recover object if any """

        tid = os.getpid()
        self.objs.setdefault(tid, {})
        self.objs[tid].setdefault(self.name, {})
        return self.objs[tid][self.name].get(key, None)

    def initialize_connection(self, expiration, verification, **kwargs):

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

    def set_models_to_service(self, obj):

        for name, model in self.models.items():
            # Save attribute inside class with the same name
            log.debug("Injecting model '{}'", name)
            setattr(obj, name, model)
        obj.models = self.models

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
            obj = self.initialize_connection(expiration, verification)
            self.set_models_to_service(obj)
            return obj

        unique_hash = str(sorted(kwargs.items()))

        obj = self.get_object(key=unique_hash)

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
        self.set_models_to_service(obj)
        self.set_object(obj=obj, key=unique_hash)
        return obj
