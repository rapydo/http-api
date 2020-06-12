import abc
import threading
from datetime import datetime, timedelta

from flask import _app_ctx_stack as stack

from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log


class Connector(metaclass=abc.ABCMeta):

    models = {}  # I get models on a cls level, instead of instances

    def __init__(self, app):

        self.objs = {}
        self.name = self.__class__.__name__.lower()

        self.app = app
        self.init_app(app)

    # Optional: you can override this method to implement initialization at class level
    # For example it is used in Celery to inject tasks into the Connector class
    @classmethod
    def init_class(cls):
        pass

    @abc.abstractmethod
    def get_connection_exception(self):  # pragma: no cover
        return None

    @abc.abstractmethod
    def connect(self, **kwargs):  # pragma: no cover
        return

    @abc.abstractmethod
    def initialize(self):  # pragma: no cover
        pass

    @abc.abstractmethod
    def destroy(self):  # pragma: no cover
        pass

    def close_connection(self):
        """ override this method if you must close
        your connection after each request"""

        # obj = self.get_object()
        # obj.close()
        self.set_object(obj=None)  # it could be overidden

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
                        log.verbose("Overriding model {}", key)
                        cls.models[key] = model
                        continue

                # Otherwise just append
                cls.models[key] = model

        if len(cls.models) > 0:
            log.verbose("Loaded models")

    @classmethod
    def set_variables(cls, envvars):
        cls.variables = envvars

    def init_app(self, app):
        app.teardown_appcontext(self.teardown)

    @staticmethod
    def get_key(key: str) -> str:
        """ Make sure reference and key are strings """

        return f"{threading.get_native_id()}:{key}"

    def set_object(self, obj, key="[]") -> None:
        """ set object into internal array """

        h = self.get_key(key)
        self.objs[h] = obj

    def get_object(self, key="[]"):
        """ recover object if any """

        h = self.get_key(key)
        return self.objs.get(h, None)

    def initialize_connection(self, **kwargs):

        obj = None

        exceptions = self.get_connection_exception()
        if exceptions is None:
            exceptions = (BaseException,)

        try:
            obj = self.connect(**kwargs)
        except exceptions as e:
            log.error("{} raised {}: {}", self.name, e.__class__.__name__, e)
            raise ServiceUnavailable({"Service Unavailable": "Internal server error"})

        obj.connection_time = datetime.now()
        return obj

    def set_models_to_service(self, obj):

        for name, model in self.models.items():
            # Save attribute inside class with the same name
            log.verbose("Injecting model '{}'", name)
            setattr(obj, name, model)
        obj.models = self.models

    def teardown(self, exception):
        # if self.get_object() is not None:
        #     self.close_connection()
        pass

    def get_instance(self, **kwargs):

        # When context is empty this is a connection at loading time
        # Do not save it
        if stack.top is None:
            log.verbose("First connection for {}", self.name)
            # can raise ServiceUnavailable exception
            obj = self.initialize_connection()
            self.set_models_to_service(obj)
            return obj

        # Parameters
        global_instance = kwargs.pop("global_instance", None)
        # Deprecated since 0.7.4
        if global_instance is not None:  # pragma: no cover
            log.warning("Deprecated use of global_instance flag")

        isauth = kwargs.pop("authenticator", None)
        # Deprecated since 0.7.4
        if isauth is not None:  # pragma: no cover
            log.warning("Deprecated use of isauth flag")

        cache_expiration = kwargs.pop("cache_expiration", None)

        unique_hash = str(sorted(kwargs.items()))

        obj = self.get_object(key=unique_hash)

        if obj and cache_expiration:
            now = datetime.now()
            exp = timedelta(seconds=cache_expiration)

            if now >= obj.connection_time + exp:
                log.info("Cache expired for {}", self)
                obj = None

        if obj:
            return obj

        # can raise ServiceUnavailable exception
        obj = self.initialize_connection(**kwargs)
        self.set_models_to_service(obj)
        self.set_object(obj=obj, key=unique_hash)
        return obj


def get_debug_instance(MyClass):
    """
    Obtain a debug instance from any flask ext we have in the app

    e.g.
    from restapi.connectors import get_debug_instance
    from restapi.connectors.celery import CeleryExt
    obj = get_debug_instance(CeleryExt)
    """

    #######
    # NOTE: impors are needed here for logging to work correctly
    from restapi.services.detect import detector

    log.verbose("Detector imported: {}", detector)  # avoid PEP complaints
    # FIXME: e.g. importing-programmatically
    # docs.python.org/3/library/importlib.html

    #######
    instance = MyClass()
    obj = instance.initialize_connection()
    instance.set_models_to_service(obj)
    return obj
