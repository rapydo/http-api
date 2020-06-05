import abc
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
    def preconnect(self, **kwargs):  # pragma: no cover
        return True

    @abc.abstractmethod
    def connect(self, **kwargs):  # pragma: no cover
        return

    @abc.abstractmethod
    def postconnect(self, obj, **kwargs):  # pragma: no cover
        return True

    @abc.abstractmethod
    def initialize(self):  # pragma: no cover
        pass

    @abc.abstractmethod
    def destroy(self):  # pragma: no cover
        pass

    def close_connection(self, ctx):
        """ override this method if you must close
        your connection after each request"""

        # obj = self.get_object(ref=ctx)
        # obj.close()
        self.set_object(obj=None, ref=ctx)  # it could be overidden

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
    def get_key(ref: object, key: str) -> str:
        """ Make sure reference and key are strings """

        ref = ref.__class__.__name__

        return f"{ref}{key}"

    def set_object(self, obj, ref, key='[]') -> None:
        """ set object into internal array """

        h = self.get_key(ref, key)
        self.objs[h] = obj

    def get_object(self, ref, key='[]'):
        """ recover object if any """

        h = self.get_key(ref, key)
        return self.objs.get(h, None)

    def initialize_connection(self, **kwargs):

        obj = None

        # BEFORE
        if not self.preconnect(**kwargs):  # pragma: no cover
            log.error("Unable to make preconnection for {}", self.name)
            raise ServiceUnavailable(
                {"Service Unavailable": "Internal server error"}
            )

        exceptions = self.get_connection_exception()
        if exceptions is None:
            exceptions = (BaseException,)

        try:
            obj = self.connect(**kwargs)
        except exceptions as e:
            log.error("{} raised {}: {}", self.name, e.__class__.__name__, e)
            raise ServiceUnavailable(
                {"Service Unavailable": "Internal server error"}
            )

        # AFTER
        if not self.postconnect(obj, **kwargs):  # pragma: no cover
            log.error("Unable to make postconnect for {}", self.name)
            raise ServiceUnavailable(
                {"Service Unavailable": "Internal server error"}
            )

        obj.connection_time = datetime.now()
        return obj

    def set_models_to_service(self, obj):

        for name, model in self.models.items():
            # Save attribute inside class with the same name
            log.verbose("Injecting model '{}'", name)
            setattr(obj, name, model)
        obj.models = self.models

    def teardown(self, exception):
        ctx = stack.top
        if self.get_object(ref=ctx) is not None:
            self.close_connection(ctx)

    def get_instance(self, **kwargs):

        # Parameters
        global_instance = kwargs.pop('global_instance', False)
        isauth = kwargs.pop('authenticator', False)
        cache_expiration = kwargs.pop('cache_expiration', None)

        # When not using the context, this is the first connection
        if stack.top is None:
            # First connection, before any request
            # can raise ServiceUnavailable exception
            obj = self.initialize_connection()
            self.set_object(obj=obj, ref=self)

            log.verbose("First connection for {}", self.name)

            self.set_models_to_service(obj)

            return obj

        obj = None
        ref = self if isauth or global_instance else stack.top
        unique_hash = str(sorted(kwargs.items()))

        if not isauth:
            obj = self.get_object(ref=ref, key=unique_hash)

        if obj and cache_expiration:
            now = datetime.now()
            exp = timedelta(seconds=cache_expiration)

            if now >= obj.connection_time + exp:
                log.info("Cache expired for {}", self)
                obj = None

        if not obj:
            # can raise ServiceUnavailable exception
            obj = self.initialize_connection(**kwargs)
            self.set_object(obj=obj, ref=ref, key=unique_hash)

        self.set_models_to_service(obj)

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
