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

AUTH_NAME = 'authentication'


class Detector:
    def __init__(self):

        self.authentication_service = Detector.get_global_var("AUTH_SERVICE")

        if self.authentication_service is None:
            log.info("No service defined for authentication")
        else:
            log.info(
                "Authentication is based on '{}' service",
                self.authentication_service
            )

        self.authentication_instance = None

        self.available_services = {}
        self.services_classes = {}
        self.connectors_instances = {}

        try:
            self.services_configuration = load_yaml_file(
                file='connectors.yaml',
                path=ABS_RESTAPI_CONFSPATH
            )
        except AttributeError as e:
            log.exit(e)

        self.load_services()

    @staticmethod
    def get_global_var(key, default=None):
        return os.environ.get(key, default)

    @staticmethod
    @lru_cache()
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
        if service_name == AUTH_NAME:
            return self.authentication_instance

        farm = self.connectors_instances.get(service_name)
        if farm is None:
            raise AttributeError("Service {} not found".format(service_name))
        instance = farm.get_instance(global_instance=global_instance, **kwargs)
        return instance

    def load_services(self):

        self.available_services[AUTH_NAME] = Detector.get_bool_from_os('AUTH_ENABLE')

        for service in self.services_configuration:

            name = service.get('name')

            variables = Detector.load_variables(prefix=name)

            connect = Detector.get_bool_envvar(variables.get("enable_connector", True))
            if not connect:
                log.info("{} connector is disabled", name)
                continue

            # Was this service enabled from the developer?
            enabled = Detector.get_bool_envvar(variables.get("enable", False))
            external = variables.get("external", False)

            self.available_services[name] = enabled or external

            if not self.available_services.get(name):
                continue

            service['variables'] = variables

            log.verbose("Looking for class {}", name)

            class_name = service.get('class')
            connector_name = service.get('name')

            # Get the existing class
            try:
                MyClass = self.load_connector(connector_name, class_name)

                # Passing variables
                MyClass.set_variables(variables)

            except AttributeError as e:
                log.error(str(e))
                log.exit('Invalid connector class: {}', class_name)

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

            # Save
            self.services_classes[name] = MyClass

            log.debug("Got class definition for {}", MyClass)

        if len(self.services_classes) < 1:
            raise KeyError("No classes were recovered!")

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

    @staticmethod
    def load_variables(prefix):

        prefix += "_"

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

    @staticmethod
    def load_connector(connector, classname):

        module_name = "{}.connectors.{}".format(BACKEND_PACKAGE, connector)
        module = Meta.get_module_from_string(
            modulestring=module_name,
            exit_on_fail=True
        )
        if module is None:
            log.exit("Failed to load {}", module_name)

        return getattr(module, classname)

    def init_services(self, app, project_init=False, project_clean=False):

        instances = {}

        for service in self.services_configuration:

            name = service.get('name')

            if not self.available_services.get(name):
                continue

            # Get connectors class and build the connector object
            Connector = self.services_classes.get(name)
            try:
                instance = Connector(app)
            except TypeError as e:
                log.exit('Your class {} is not compliant:\n{}', name, e)
            else:
                self.connectors_instances[name] = instance

            # do_init = project_init and name == self.authentication_service

            # Initialize the real service getting the first service object
            # log.debug("Initializing {} (pinit={})", name, do_init)
            # service_instance = instance.initialize(
            #     pinit=do_init,
            #     pdestroy=project_clean,
            # )
            instances[name] = instance.get_instance()

            # Injecting tasks from *vanilla_package/tasks* into the Celery Connecttor
            if name == 'celery':

                task_package = "{}.tasks".format(CUSTOM_PACKAGE)

                submodules = Meta.import_submodules_from_package(
                    task_package, exit_on_fail=True
                )
                for submodule in submodules:
                    tasks = Meta.get_celery_tasks_from_module(submodule)

                    for func_name, funct in tasks.items():
                        setattr(Connector, func_name, funct)

        if self.authentication_service is None:
            log.warning("No authentication service configured")
        elif self.authentication_service not in instances:
            log.exit("Auth service '{}' is unreachable", self.authentication_service)

        auth_module = Meta.get_authentication_module(self.authentication_service)
        db = instances[self.authentication_service]
        self.authentication_instance = auth_module.Authentication(db)

        # Only once in a lifetime
        if project_init:

            connector = self.connectors_instances[self.authentication_service]
            log.debug("Initializing {}", self.authentication_service)
            connector.initialize()

            with app.app_context():
                self.authentication_instance.init_users_and_roles()
                log.info("Initialized authentication module")

            self.project_initialization(instances, app=app)

        if project_clean:
            connector = self.connectors_instances[self.authentication_service]
            log.debug("Destroying {}", self.authentication_service)
            connector.destroy()

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
