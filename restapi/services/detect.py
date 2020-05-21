# -*- coding: utf-8 -*-

"""
Detect which services are running, by testing environment variables
set with containers/docker-compose/do.py

Note: docker links and automatic variables removed as unsafe with compose V3

"""

import os
from functools import lru_cache

from restapi.confs import EXTENDED_PROJECT_DISABLED
from restapi.confs import BACKEND_PACKAGE, CUSTOM_PACKAGE, EXTENDED_PACKAGE
from restapi.connectors import Connector
from restapi.utilities.meta import Meta
from restapi.confs import ABS_RESTAPI_PATH
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

        self.services = {}

        path = os.path.join(ABS_RESTAPI_PATH, 'connectors')
        self.load_services(path, "restapi.connectors")

    @staticmethod
    def get_global_var(key, default=None):
        return os.getenv(key, default)

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

        bool_var = os.getenv(name, False)
        return Detector.get_bool_envvar(bool_var)

    def get_service_instance(self, service_name, global_instance=True, **kwargs):
        if service_name == AUTH_NAME:
            return self.authentication_instance

        service = self.services.get(service_name)
        if service is None:
            raise AttributeError("Service {} not found".format(service_name))

        if not service.get('available', False):
            raise AttributeError("Service {} not available".format(service_name))

        farm = service.get('instance')
        if farm is None:
            raise AttributeError("Service {} not available".format(service_name))
        instance = farm.get_instance(global_instance=global_instance, **kwargs)
        return instance

    def load_services(self, path, modules):

        self.services[AUTH_NAME] = {
            'available': Detector.get_bool_from_os('AUTH_ENABLE')
        }

        # Looking for all file in apis folder
        for connector in os.listdir(path):
            if not os.path.isdir(os.path.join(path, connector)):
                continue
            if connector.startswith("_"):
                continue

            # This is the only exception... we should rename sqlalchemy as alchemy
            if connector == 'sqlalchemy':
                prefix = 'alchemy'
            else:
                prefix = connector

            variables = Detector.load_variables(prefix=prefix)

            if not Detector.get_bool_envvar(variables.get("enable_connector", True)):
                log.info("{} connector is disabled", connector)
                continue

            # Was this service enabled from the developer?
            enabled = Detector.get_bool_envvar(variables.get("enable", False))
            external = variables.get("external", False)

            self.services.setdefault(connector, {})
            self.services[connector]['available'] = enabled or external

            if not self.services[connector]['available']:
                continue

            log.verbose("Looking for connector class in {}/{}", path, connector)
            module = Meta.get_module_from_string("{}.{}".format(modules, connector))
            classes = Meta.get_new_classes_from_module(module)
            for class_name, connector_class in classes.items():
                if not issubclass(connector_class, Connector):
                    continue

                log.verbose("Found connector clas: {}", class_name)
                break
            else:
                log.error("No connector class found in {}/{}", path, connector)
                self.services[connector]['available'] = False
                continue

            self.services[connector]['variables'] = variables

            connector_class.set_variables(variables)

            models_file = os.path.join(path, connector, "models.py")
            if os.path.isfile(models_file):

                base_models = Meta.import_models(
                    connector, BACKEND_PACKAGE, exit_on_fail=True
                )
                if EXTENDED_PACKAGE == EXTENDED_PROJECT_DISABLED:
                    extended_models = {}
                else:
                    extended_models = Meta.import_models(
                        connector, EXTENDED_PACKAGE, exit_on_fail=False
                    )
                custom_models = Meta.import_models(
                    connector, CUSTOM_PACKAGE, exit_on_fail=False
                )

                connector_class.set_models(base_models, extended_models, custom_models)

            self.services[connector]['class'] = connector_class

            log.debug("Got class definition for {}", connector_class)

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

        for connector_name, service in self.services.items():

            if not service.get('available', False):
                continue

            # Get connectors class and build the connector object
            ConnectorClass = service.get('class')

            if ConnectorClass is None:
                if connector_name != AUTH_NAME:  # pragma: no cover
                    log.exit(
                        "Connector misconfiguration {} {}",
                        connector_name,
                        service
                    )
                continue

            try:
                instance = ConnectorClass(app)
            except TypeError as e:
                log.exit('Your class {} is not compliant:\n{}', connector_name, e)

            self.services[connector_name]['instance'] = instance

            instances[connector_name] = instance.get_instance()

            ConnectorClass.init_class()

        if self.authentication_service is None:
            log.warning("No authentication service configured")
        elif self.authentication_service not in instances:
            log.exit("Auth service '{}' is unreachable", self.authentication_service)

        if self.authentication_service is not None:
            auth_module = Meta.get_authentication_module(self.authentication_service)
            db = instances[self.authentication_service]
            self.authentication_instance = auth_module.Authentication(db)

            # Only once in a lifetime
            if project_init:

                connector = instances[self.authentication_service]
                log.debug("Initializing {}", self.authentication_service)
                connector.initialize()

                with app.app_context():
                    self.authentication_instance.init_users_and_roles()
                    log.info("Initialized authentication module")

                self.project_initialization(instances, app=app)

            if project_clean:
                connector = instances[self.authentication_service]
                log.debug("Destroying {}", self.authentication_service)
                connector.destroy()

    def check_availability(self, name):

        if '.' in name:
            # In this case we are receiving a module name
            # e.g. restapi.services.mongodb
            name = name.split('.')[::-1][0]

        if name not in self.services:
            return False

        return self.services.get(name).get('available', False)

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
