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
from restapi.utilities.logs import log


class Detector:
    def __init__(self):

        self.authentication_service = None
        self.authentication_name = 'authentication'
        self.services_configuration = []
        self.services_classes = {}
        self.connectors_instances = {}
        self.available_services = {}
        self.check_configuration()
        self.load_classes()

    @staticmethod
    def get_global_var(key, default=None):
        return os.environ.get(key, default)

    @staticmethod
    @lru_cache(maxsize=None)  # avoid calling it twice for the same var
    def get_bool_envvar(bool_var):

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
        if isinstance(bool_var, str):
            # false / False / FALSE
            if bool_var.lower() == 'false':
                return False
            # any non empty string has to be considered True
            if len(bool_var) > 0:
                return True

        return False

    @staticmethod
    @lru_cache(maxsize=None)  # avoid calling it twice for the same var
    def get_bool_from_os(name):

        bool_var = os.environ.get(name, False)
        return Detector.get_bool_envvar(bool_var)

    def get_service_instance(self, service_name, global_instance=True, **kwargs):
        farm = self.connectors_instances.get(service_name)
        if farm is None:
            raise AttributeError("Service {} not found".format(service_name))
        instance = farm.get_instance(global_instance=global_instance, **kwargs)
        return instance

    def check_configuration(self):

        try:
            self.services_configuration = load_yaml_file(
                file='connectors.yaml', path=ABS_RESTAPI_CONFSPATH)
        except AttributeError as e:
            log.exit(e)

        for service in self.services_configuration:

            name = service.get('name')
            prefix = "{}_".format(service.get('prefix'))

            variables = Detector.load_variables(prefix=prefix)

            connect = Detector.get_bool_envvar(variables.get("enable_connector", True))
            if not connect:
                log.info("{} connector is disabled", name)
                continue

            # Was this service enabled from the developer?
            enabled = Detector.get_bool_envvar(variables.get("enable", False))
            external = variables.get("external", False)

            self.available_services[name] = enabled or external

            if self.available_services[name]:

                service['variables'] = variables

                # set auth service
                if name == self.authentication_name:
                    self.authentication_service = variables.get('service')

        if self.authentication_service is None:
            log.info("No service defined for authentication")
        else:
            log.info(
                "Authentication is based on '{}' service",
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
    def load_variables(prefix):

        variables = {
            'external': False
        }

        for var, value in os.environ.items():

            var = var.lower()

            if not var.startswith(prefix):
                continue

            # Fix key and value before saving
            key = var[len(prefix):]
            # One thing that we must avoid is any quote around our value
            value = value.strip('"').strip("'")
            # save
            variables[key] = value

            if key == 'host' and not value.endswith('.dockerized.io'):
                variables['external'] = True
                log.verbose("Service {} detected as external: {}", prefix, value)

        return variables

    def load_connector(self, connector, classname):

        module_name = "{}.connectors.{}".format(BACKEND_PACKAGE, connector)
        module = Meta.get_module_from_string(
            modulestring=module_name,
            exit_on_fail=True
        )
        if module is None:
            log.exit("Failed to load {}", module_name)

        return getattr(module, classname)

    def load_classes(self):

        for service in self.services_configuration:

            name = service.get('name')

            if not self.available_services.get(name):
                continue
            log.verbose("Looking for class {}", name)

            variables = service.get('variables')
            class_name = service.get('class')
            connector_name = service.get('name')

            # Get the existing class
            try:
                MyClass = self.load_connector(connector_name, class_name)

                # Passing variables
                MyClass.set_variables(variables)

                if service.get('load_models'):

                    base_models = Meta.import_models(
                        name, BACKEND_PACKAGE, exit_on_fail=True
                    )
                    if EXTENDED_PACKAGE == EXTENDED_PROJECT_DISABLED:
                        extended_models = {}
                    else:
                        extended_models = Meta.import_models(
                            name, EXTENDED_PACKAGE, exit_on_fail=False
                        )
                    custom_models = Meta.import_models(
                        name, CUSTOM_PACKAGE, exit_on_fail=False
                    )

                    MyClass.set_models(base_models, extended_models, custom_models)

            except AttributeError as e:
                log.error(str(e))
                log.exit('Invalid connector class: {}', class_name)

            # Save
            self.services_classes[name] = MyClass
            log.debug("Got class definition for {}", MyClass)

        if len(self.services_classes) < 1:
            raise KeyError("No classes were recovered!")

        return self.services_classes

    def init_services(
        self, app, worker_mode=False, project_init=False, project_clean=False
    ):

        instances = {}
        auth_backend = None

        for service in self.services_configuration:

            name = service.get('name')

            if not self.available_services.get(name):
                continue

            if name == self.authentication_name and auth_backend is None:
                if self.authentication_service is None:
                    log.warning("No authentication")
                    continue
                else:
                    log.exit(
                        "Auth service '{}' is unreachable".format(
                            self.authentication_service)
                    )

            args = {}
            if name == 'celery':
                args['worker_mode'] = worker_mode

            # Get connectors class and build the connector object
            Connector = self.services_classes.get(name)
            try:
                instance = Connector(app, **args)
            except TypeError as e:
                log.exit('Your class {} is not compliant:\n{}', name, e)
            else:
                self.connectors_instances[name] = instance

            if not project_init:
                do_init = False
            elif name == self.authentication_service:
                do_init = True
            elif name == self.authentication_name:
                do_init = True
            else:
                do_init = False

            # Initialize the real service getting the first service object
            log.debug("Initializing {} (pinit={})", name, do_init)
            service_instance = instance.custom_init(
                pinit=do_init, pdestroy=project_clean, abackend=auth_backend
            )
            instances[name] = service_instance

            if name == self.authentication_service:
                auth_backend = service_instance

            # Injecting tasks from *vanilla_package/tasks* into the Celery Connecttor
            if name == 'celery':
                do_init = True

                task_package = "{}.tasks".format(CUSTOM_PACKAGE)

                submodules = Meta.import_submodules_from_package(
                    task_package, exit_on_fail=True
                )
                for submodule in submodules:
                    tasks = Meta.get_celery_tasks_from_module(submodule)

                    for func_name, funct in tasks.items():
                        setattr(Connector, func_name, funct)

        if len(self.connectors_instances) < 1:
            raise KeyError("No instances available for modules")

        # Only once in a lifetime
        if project_init:
            self.project_initialization(instances, app=app)

        return self.connectors_instances

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
            module_path = "{}.{}.{}".format(
                CUSTOM_PACKAGE,
                'initialization',
                'initialization',
            )
            module = Meta.get_module_from_string(module_path)
            Initializer = Meta.get_class_from_string(
                'Initializer', module, skip_error=True
            )
            if Initializer is None:
                log.debug("No custom init available")
            else:
                try:
                    Initializer(instances, app=app)
                except BaseException as e:
                    log.error("Errors during custom initialization: {}", e)
                else:
                    log.info("Vanilla project has been initialized")

        except BaseException:
            log.debug("No custom init available")


detector = Detector()
