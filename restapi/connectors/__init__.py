import abc
import os
from datetime import datetime, timedelta
from typing import Dict

# mypy: ignore-errors
from flask import _app_ctx_stack as stack

from restapi.exceptions import ServiceUnavailable
from restapi.utilities import print_and_exit
from restapi.utilities.logs import log


class Connector(metaclass=abc.ABCMeta):

    models = {}
    # will contain:
    # objs = {
    #     'thread-id': {
    #         'ConnectorName': {
    #             'params-unique-key': instance
    #         }
    #     }
    # }
    objs = {}

    def __init__(self, app):

        self.name = self.__class__.__name__.lower()
        self.app = app
        self.variables: Dict[str, str] = {}
        # Will be modified by self.disconnect()
        self.disconnected = False

        # to implement request-level instances:
        # 1 . implement a flag or new get_intance to change the key identifier
        #     i.e. instead of thread.get_native_id set something identifying the request
        #          probably based on stack.top
        # 2 . register this teardown for such intances
        # 3 . call disconnect for such objects
        # app.teardown_appcontext(self.teardown)

    # def teardown(self, exception):
    #     if obj := self.get_object('identify the request level object') is not None:
    #         obj.disconnect()

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

    def get_object(self, key="[]"):
        """ recover object if any """

        tid = os.getpid()
        self.objs.setdefault(tid, {})
        self.objs[tid].setdefault(self.name, {})
        return self.objs[tid][self.name].get(key, None)

    def initialize_connection(self, **kwargs):

        # Create a new instance of itself
        obj = self.__class__(self.app)

        exceptions = obj.get_connection_exception()
        if exceptions is None:
            exceptions = (BaseException,)

        try:
            obj = obj.connect(**kwargs)
        except exceptions as e:
            log.error("{} raised {}: {}", obj.name, e.__class__.__name__, e)
            raise ServiceUnavailable({"Service Unavailable": "Internal server error"})

        obj.connection_time = datetime.now()
        return obj

    def set_models_to_service(self, obj):

        for name, model in self.models.items():
            # Save attribute inside class with the same name
            log.debug("Injecting model '{}'", name)
            setattr(obj, name, model)
        obj.models = self.models

    def get_instance(self, cache_expiration=None, verify=False, **kwargs):

        # When context is empty this is a connection at loading time
        # Do not save it
        if stack.top is None:
            log.debug("First connection for {}", self.name)
            # can raise ServiceUnavailable exception
            obj = self.initialize_connection()
            self.set_models_to_service(obj)
            return obj

        unique_hash = str(sorted(kwargs.items()))

        obj = self.get_object(key=unique_hash)

        if obj and cache_expiration:
            now = datetime.now()
            exp = timedelta(seconds=cache_expiration)

            if now >= obj.connection_time + exp:
                log.info("Cache expired for {}", self.name)
                obj.disconnect()
                obj = None

        if obj and verify and not obj.is_connected():
            log.warning(
                "{} is no longer connected, creating a new connection", self.name
            )
            obj.disconnected = True

        if obj and not obj.disconnected:
            return obj

        # can raise ServiceUnavailable exception
        obj = self.initialize_connection(**kwargs)
        self.set_models_to_service(obj)
        self.set_object(obj=obj, key=unique_hash)
        return obj
