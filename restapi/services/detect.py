# -*- coding: utf-8 -*-

"""
Detect which services are running, by testing environment variables
set with containers/docker-compose/do.py

Note: docker links and automatic variables removed as unsafe with compose V3

"""

import os
from functools import lru_cache

from restapi.confs import ABS_RESTAPI_CONFSPATH, EXTENDED_PROJECT_DISABLED
from restapi.confs import BACKEND_PACKAGE, CUSTOM_PACKAGE, EXTENDED_PACKAGE
from restapi.utilities.meta import Meta
from restapi.utilities.configuration import load_yaml_file
from restapi.utilities.logs import get_logger

log = get_logger(__name__)


class Detector(object):
    def __init__(self, config_file_name='services'):

        self.authentication_service = None
        self.authentication_name = 'authentication'
        self.task_service_name = 'celery'
        self.modules = []
        self.services_configuration = []
        self.services = {}
        self.services_classes = {}
        self.extensions_instances = {}
        self.available_services = {}
        self.meta = Meta()
        self.check_configuration(config_file_name)
        self.load_classes()

    @staticmethod
    def get_global_var(key, default=None):
        return os.environ.get(key, default)

    @staticmethod
    @lru_cache(maxsize=None)  # avoid calling it twice for the same var
    def get_bool_from_os(name):

        bool_var = os.environ.get(name, False)
        if isinstance(bool_var, bool):
            return bool_var

        # if not directly a bool, try an interpretation
        # INTEGERS
        try:
            tmp = int(bool_var)
            return bool(tmp)
        except ValueError:
            pass

        # STRINGS
        # any non empty string with a least one char
        # has to be considered True
        if isinstance(bool_var, str) and len(bool_var) > 0:
            return True

        return False

    @staticmethod
    def prefix_name(service):
        return service.get('name'), service.get('prefix').lower() + '_'

    def check_configuration(self, config_file_name):

        self.services_configuration = load_yaml_file(
            file=config_file_name,
            path=ABS_RESTAPI_CONFSPATH,
            logger=True,
        )

        for service in self.services_configuration:

            name, prefix = self.prefix_name(service)

            # Was this service enabled from the developer?
            enable_var = str(prefix + 'enable').upper()
            self.available_services[name] = self.get_bool_from_os(enable_var)

            if self.available_services[name]:

                # read variables
                variables = self.load_variables(service, enable_var, prefix)
                service['variables'] = variables

                # set auth service
                if name == self.authentication_name:
                    self.authentication_service = variables.get('service')

        if self.authentication_service is None:
            log.warning("no service defined behind authentication")
            # raise AttributeError("no service defined behind authentication")
        else:
            log.info(
                "Authentication based on '%s' service",
                self.authentication_service
            )

    @staticmethod
    def load_group(label):

        variables = {}
        for var, value in os.environ.items():
            var = var.lower()
            if var.startswith(label):
                key = var[len(label):].strip('_')
                value = value.strip('"').strip("'")
                variables[key] = value
        return variables

    def output_service_variables(self, service_name):
        service_class = self.services_classes.get(service_name, {})
        try:
            return service_class.variables
        except BaseException:
            return {}

    @staticmethod
    def load_variables(service, enable_var=None, prefix=None):

        variables = {}
        host = None

        if prefix is None:
            _, prefix = Detector.prefix_name(service)

        for var, value in os.environ.items():
            if enable_var is not None and var == enable_var:
                continue
            var = var.lower()

            # This is the case when a variable belongs to a service 'prefix'
            if var.startswith(prefix):

                # Fix key and value before saving
                key = var[len(prefix) :]
                # One thing that we must avoid is any quote around our value
                value = value.strip('"').strip("'")
                # save
                variables[key] = value

                if key == 'host':
                    host = value

        # Verify if service is EXTERNAL
        variables['external'] = False
        if isinstance(host, str):  # and host.count('.') > 2:
            if not host.endswith('dockerized.io'):
                variables['external'] = True
                log.verbose("Service %s detected as external: %s", service, host)

        return variables

    def load_class_from_module(self, classname='BaseInjector', service=None):

        if service is None:
            flaskext = ''
        else:
            flaskext = '.' + service.get('extension')

        # Try inside our extensions
        module = Meta.get_module_from_string(
            modulestring=BACKEND_PACKAGE + '.flask_ext' + flaskext, exit_on_fail=True
        )
        if module is None:
            log.exit("Missing %s for %s", flaskext, service)

        return getattr(module, classname)

    def load_classes(self):

        for service in self.services_configuration:

            name, _ = self.prefix_name(service)

            if not self.available_services.get(name):
                continue
            log.verbose("Looking for class %s", name)

            variables = service.get('variables')
            ext_name = service.get('class')

            # Get the existing class
            try:
                MyClass = self.load_class_from_module(ext_name, service=service)

                # Passing variables
                MyClass.set_variables(variables)

                if service.get('load_models'):

                    base_models = self.meta.import_models(
                        name, BACKEND_PACKAGE, exit_on_fail=True
                    )
                    if EXTENDED_PACKAGE == EXTENDED_PROJECT_DISABLED:
                        extended_models = {}
                    else:
                        extended_models = self.meta.import_models(
                            name, EXTENDED_PACKAGE, exit_on_fail=False
                        )

                    custom_models = self.meta.import_models(
                        name, CUSTOM_PACKAGE, exit_on_fail=False
                    )

                    MyClass.set_models(base_models, extended_models, custom_models)

            except AttributeError as e:
                log.error(str(e))
                log.exit('Invalid Extension class: %s', ext_name)

            # Save
            self.services_classes[name] = MyClass
            log.debug("Got class definition for %s", MyClass)

        if len(self.services_classes) < 1:
            raise KeyError("No classes were recovered!")

        return self.services_classes

    def init_services(
        self, app, worker_mode=False, project_init=False, project_clean=False
    ):

        instances = {}
        auth_backend = None

        for service in self.services_configuration:

            name, _ = self.prefix_name(service)

            if not self.available_services.get(name):
                continue

            if name == self.authentication_name and auth_backend is None:
                if self.authentication_service is None:
                    log.warning("No authentication")
                    continue
                else:
                    log.exit(
                        "Auth service '%s' seems unreachable"
                        % self.authentication_service
                    )

            args = {}
            if name == self.task_service_name:
                args['worker_mode'] = worker_mode

            # Get extension class and build the extension object
            ExtClass = self.services_classes.get(name)
            try:
                ext_instance = ExtClass(app, **args)
            except TypeError as e:
                log.exit('Your class %s is not compliant:\n%s', name, e)
            else:
                self.extensions_instances[name] = ext_instance

            if not project_init:
                do_init = False
            elif name == self.authentication_service:
                do_init = True
            elif name == self.authentication_name:
                do_init = True
            else:
                do_init = False

            # Initialize the real service getting the first service object
            log.debug("Initializing %s (pinit=%s)", name, do_init)
            service_instance = ext_instance.custom_init(
                pinit=do_init, pdestroy=project_clean, abackend=auth_backend
            )
            instances[name] = service_instance

            if name == self.authentication_service:
                auth_backend = service_instance

            # NOTE: commented, looks like a duplicate from try/expect above
            # self.extensions_instances[name] = ext_instance

            # Injecting into the Celery Extension Class
            # all celery tasks found in *vanilla_package/tasks*
            if name == self.task_service_name:
                do_init = True

                task_package = "%s.tasks" % CUSTOM_PACKAGE

                submodules = self.meta.import_submodules_from_package(
                    task_package, exit_on_fail=True
                )
                for submodule in submodules:
                    tasks = Meta.get_celery_tasks_from_module(submodule)

                    for func_name, funct in tasks.items():
                        setattr(ExtClass, func_name, funct)

        if len(self.extensions_instances) < 1:
            raise KeyError("No instances available for modules")

        # Only once in a lifetime
        if project_init:
            self.project_initialization(instances, app=app)

        return self.extensions_instances

    def load_injector_modules(self):

        for service in self.services_configuration:

            name, _ = self.prefix_name(service)
            if not self.available_services.get(name):
                continue

            # Module for injection
            ModuleBaseClass = self.load_class_from_module()
            # Create modules programmatically 8)
            MyModule = self.meta.metaclassing(ModuleBaseClass, service.get('injector'))

            # Recover class
            MyClass = self.services_classes.get(name)
            if MyClass is None:
                raise AttributeError("No class found for %s" % name)
            MyModule.set_extension_class(MyClass)
            self.modules.append(MyModule)

        return self.modules

    def check_availability(self, name):

        if '.' in name:
            # In this case we are receiving a module name
            # e.g. restapi.services.mongodb
            name = name.split('.')[::-1][0]

        return self.available_services.get(name)

    @classmethod
    def project_initialization(self, instances, app=None):
        """ Custom initialization of your project

        Please define your class Initializer in
        project/YOURPROJECT/backend/initialization/initialization.py
        """

        try:
            # NOTE: this might be a pattern
            # see in meta.py:get_customizer_class
            module_path = "%s.%s.%s" % (
                CUSTOM_PACKAGE,
                'initialization',
                'initialization',
            )
            module = Meta.get_module_from_string(module_path, debug_on_fail=False)
            meta = Meta()
            Initializer = meta.get_class_from_string(
                'Initializer', module, skip_error=True
            )
            if Initializer is None:
                log.debug("No custom init available")
            else:
                try:
                    Initializer(instances, app=app)
                except BaseException as e:
                    log.error("Errors during custom initialization: %s", e)
                else:
                    log.info("Vanilla project has been initialized")

        except BaseException:
            log.debug("No custom init available")


detector = Detector()
