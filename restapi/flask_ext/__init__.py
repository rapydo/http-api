# -*- coding: utf-8 -*-

""" base in common for our flask internal extensions """

# TODO: we may create a base object for flask extensions like the injector

import abc
from datetime import datetime, timedelta
# import time
from flask import Flask, _app_ctx_stack as stack
from injector import Module, singleton, inject  # , provider
from utilities.meta import Meta
from utilities.logs import get_logger

log = get_logger(__name__)


class BaseExtension(metaclass=abc.ABCMeta):

    models = {}  # I get models on a cls level, instead of instances
    meta = Meta()

    def __init__(self, app=None, **kwargs):

        self.objs = {}
        self.set_name()
        self.args = kwargs

        self.app = app
        if app is not None:
            self.init_app(app)

    def set_name(self):
        """ a different name for each extended object """
        self.name = self.__class__.__name__.lower()
        log.very_verbose("Opening service instance of %s" % self.name)

    @classmethod
    def set_models(cls, base_models, custom_models):

        # Join models as described by issue #16
        cls.models = base_models
        for key, model in custom_models.items():

            # Verify if overriding
            if key in base_models.keys():
                original_model = base_models[key]
                # Override
                if issubclass(model, original_model):
                    log.very_verbose("Overriding model %s" % key)
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

    def connect(self, **kwargs):

        obj = None

        # BEFORE
        ok = self.pre_connection(**kwargs)

        if not ok:
            log.critical("Unable to make preconnection for %s", self.name)
            return obj

        # Try until it's connected
        if len(kwargs) > 0:
            obj = self.custom_connection(**kwargs)
        else:
            obj = self.retry()
            log.info("Connected! %s", self.name)

        # AFTER
        self.post_connection(obj, **kwargs)

        obj.connection_time = datetime.now()
        return obj

    def set_models_to_service(self, obj):

        if len(self.models) < 1 and self.__class__.__name__ == 'NeoModel':
            raise Exception()

        for name, model in self.models.items():
            # Save attribute inside class with the same name
            log.very_verbose("Injecting model '%s'" % name)
            setattr(obj, name, model)
            obj.models = self.models

        return obj

    def set_connection_exception(self):
        return None

    def retry(self, retry_interval=3, max_retries=-1):
        retry_count = 0

        # Get the exception which will signal a missing connection
        exceptions = self.set_connection_exception()
        if exceptions is None:
            exceptions = (BaseException, )

        while max_retries != 0 or retry_count < max_retries:

            retry_count += 1
            if retry_count > 1:
                log.verbose("testing again in %s secs", retry_interval)

            try:
                obj = self.custom_connection()
            except exceptions as e:
                log.error("Catched: %s(%s)", e.__class__.__name__, e)
                # NOTE: if you critical_exit uwsgi will not show this line
                log.critical("Service '%s' not available", self.name)
                log.exit()
                # raise e
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
        log.very_verbose("instance hash: %s" % unique_hash)

        # When not using the context, this is the first connection
        if ctx is None:
            # First connection, before any request
            obj = self.connect()
            if obj is None:
                return None
            # self.initialization(obj=obj)
            self.set_object(obj=obj, ref=ref)

            log.verbose("First connection for %s" % self.name)

        else:
            # isauth = 'Authenticator' == self.__class__.__name__

            if not isauth:
                if not global_instance:
                    ref = ctx

                obj = self.get_object(ref=ref, key=unique_hash)

            if obj is not None and cache_expiration is not None:
                now = datetime.now()
                exp = timedelta(seconds=cache_expiration)

                if now < obj.connection_time + exp:
                    log.very_verbose("Cache still fresh for %s" % (self))
                else:
                    log.warning("Cache expired for %s", (self))
                    obj = None

            if obj is None:
                obj = self.connect(**kwargs)
                if obj is None:
                    return None
                self.set_object(obj=obj, ref=ref, key=unique_hash)
            else:
                pass

            log.very_verbose("Instance %s(%s)" % (ref.__class__.__name__, obj))

        obj = self.set_models_to_service(obj)

        return obj

    ############################
    # OPTIONALLY
    # to be executed only at init time?

    def pre_connection(self, **kwargs):
        return True

    def post_connection(self, obj=None, **kwargs):
        return True

    def close_connection(self, ctx):
        """ override this method if you must close
        your connection after each request"""

        # obj = self.get_object(ref=ctx)
        # obj.close()
        self.set_object(obj=None, ref=ctx)  # it could be overidden

    ############################
    # To be overridden
    @abc.abstractmethod
    def custom_connection(self, **kwargs):
        return

    ############################
    # Already has default
    def custom_init(self, **kwargs):
        """
        The real signature:
        def custom_init(self, pinit=False, pdestroy=False, abackend=None):

            - A backend is needed for non-standalone services
                e.g. authentication module
            - Project initialization/removal could be used here
                or carried on to low levels;
                they get activated by specific flask cli commands

        """
        return self.get_instance()


class BaseInjector(Module):

    # def __init__(self, **kwargs):
    #     self.args = kwargs

    @classmethod
    def set_extension_class(cls, ExtensionClass):
        if hasattr(cls, '_extClass'):
            raise("Extension class was already set")
        cls._extClass = ExtensionClass

    @classmethod
    def get_extension_class(cls):
        if not hasattr(cls, '_extClass'):
            raise("Extension class was not set at 'service detection' time")
        return cls._extClass

    # @provider
    # @singleton
    # def provide_ext(self, app: Flask) -> BaseExtension:
    @inject
    def configure(self, binder, app: Flask):

        # TODO: recheck soon on new versions of Flask-Injector...

        # Get the Flask extension and its instance
        MyClass = self.get_extension_class()
        # my_instance = MyClass(app, **self.args)
        return binder.bind(MyClass, to=MyClass(app), scope=singleton)
        # return my_instance


def get_debug_instance(MyClass):
    """
    Obtain a debug instance from any flask ext we have in the app

    e.g. from restapi.flask_ext.flask_celery import CeleryExt
    obj = get_debug_instance(CeleryExt)
    """

    #######
    # NOTE: impors are needed here for logging to work correctly
    from utilities.logs import get_logger
    from restapi.services.detect import detector
    detector  # avoid PEP complaints
    get_logger
    # FIXME: e.g. importing-programmatically
    # docs.python.org/3/library/importlib.html

    #######
    instance = MyClass()
    obj = instance.connect()
    obj = instance.set_models_to_service(obj)
    return obj
