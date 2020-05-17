# -*- coding: utf-8 -*-

import abc
from datetime import datetime, timedelta

from flask import _app_ctx_stack as stack
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
    def get_connection_exception(self):
        return None

    @abc.abstractmethod
    def preconnect(self, **kwargs):
        return True

    @abc.abstractmethod
    def connect(self, **kwargs):
        return

    @abc.abstractmethod
    def postconnect(self, obj, **kwargs):
        return True

    @abc.abstractmethod
    def initialize(self):
        pass

    @abc.abstractmethod
    def destroy(self):
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

    def pre_object(self, ref, key):
        """ Make sure reference and key are strings """

        if ref is None:
            ref = self.__class__.__name__
        elif isinstance(ref, object):
            ref = ref.__class__.__name__
        elif not isinstance(ref, str):
            ref = str(ref)

        if not isinstance(key, str):
            key = str(key)

        return ref + key

    def set_object(self, obj, key='[]', ref=None):
        """ set object into internal array """

        h = self.pre_object(ref, key)
        self.objs[h] = obj
        return obj

    def get_object(self, key='[]', ref=None):
        """ recover object if any """

        h = self.pre_object(ref, key)
        obj = self.objs.get(h, None)
        return obj

    def initialize_connection(self, **kwargs):

        obj = None

        # BEFORE
        ok = self.preconnect(**kwargs)

        if not ok:
            log.critical("Unable to make preconnection for {}", self.name)
            return obj

        # Try until it's connected
        if len(kwargs) > 0:
            obj = self.connect(**kwargs)
        else:
            obj = self.retry()
            log.verbose("Connected! {}", self.name)

        # AFTER
        self.postconnect(obj, **kwargs)

        obj.connection_time = datetime.now()
        return obj

    def set_models_to_service(self, obj):

        if len(self.models) < 1 and self.__class__.__name__ == 'NeoModel':
            raise Exception()

        for name, model in self.models.items():
            # Save attribute inside class with the same name
            log.verbose("Injecting model '{}'", name)
            setattr(obj, name, model)
            obj.models = self.models

        return obj

    def retry(self, retry_interval=3, max_retries=-1):
        retry_count = 0

        # Get the exception which will signal a missing connection
        exceptions = self.get_connection_exception()
        if exceptions is None:
            exceptions = (BaseException,)

        while max_retries != 0 or retry_count < max_retries:

            retry_count += 1
            if retry_count > 1:
                log.verbose("testing again in {} secs", retry_interval)

            try:
                obj = self.connect()
            except exceptions as e:
                log.error("Catched: {}({})", e.__class__.__name__, e)
                log.exit("Service '{}' not available", self.name)
            else:
                break

            # Increment sleeps time if doing a lot of retries
            if retry_count % 3 == 0:
                log.debug("Incrementing interval")
                retry_interval += retry_interval

        return obj

    def teardown(self, exception):
        ctx = stack.top
        if self.get_object(ref=ctx) is not None:
            self.close_connection(ctx)

    def get_instance(self, **kwargs):

        # Parameters
        global_instance = kwargs.pop('global_instance', False)
        isauth = kwargs.pop('authenticator', False)
        cache_expiration = kwargs.pop('cache_expiration', None)
        # pinit = kwargs('project_initialization', False)

        # Variables
        obj = None
        ctx = stack.top
        ref = self
        unique_hash = str(sorted(kwargs.items()))

        # When not using the context, this is the first connection
        if ctx is None:
            # First connection, before any request
            obj = self.initialize_connection()
            if obj is None:
                return None
            self.set_object(obj=obj, ref=ref)

            log.verbose("First connection for {}", self.name)

        else:

            if not isauth:
                if not global_instance:
                    ref = ctx

                obj = self.get_object(ref=ref, key=unique_hash)

            if obj is not None and cache_expiration is not None:
                now = datetime.now()
                exp = timedelta(seconds=cache_expiration)

                if now < obj.connection_time + exp:
                    log.verbose("Cache is still valid for {}", self)
                else:
                    log.info("Cache expired for {}", self)
                    obj = None

            if obj is None:
                obj = self.initialize_connection(**kwargs)
                if obj is None:
                    return None
                self.set_object(obj=obj, ref=ref, key=unique_hash)
            else:
                pass

        obj = self.set_models_to_service(obj)

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
    obj = instance.set_models_to_service(obj)
    return obj
