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
from restapi.env import Env
from restapi.utilities.meta import Meta
from restapi.confs import ABS_RESTAPI_PATH
from restapi.utilities.logs import log

AUTH_NAME = 'authentication'
CONNECTORS_FOLDER = 'connectors'


class Detector:
    def __init__(self):

        self.authentication_service = Env.get("AUTH_SERVICE")

        if self.authentication_service is None:
            log.info("No service defined for authentication")
        else:
            log.info(
                "Authentication is based on '{}' service",
                self.authentication_service
            )

        self.authentication_instance = None

        self.services = {
            AUTH_NAME: {
                'available': Env.get_bool('AUTH_ENABLE')
            }
        }

        self.load_services(ABS_RESTAPI_PATH, BACKEND_PACKAGE)

        if EXTENDED_PACKAGE != EXTENDED_PROJECT_DISABLED:
            self.load_services(
                os.path.join(os.curdir, EXTENDED_PACKAGE),
                EXTENDED_PACKAGE
            )

        self.load_services(
            os.path.join(os.curdir, CUSTOM_PACKAGE),
            CUSTOM_PACKAGE
        )

    @staticmethod
    def get_global_var(key, default=None):
        # Deprecated since 0.7.4
        log.warning("Deprecated use of get_global_var, use os.getenv or Env.get")
        return os.getenv(key, default)

    @staticmethod
    @lru_cache
    def get_bool_envvar(bool_var):
        # Deprecated since 0.7.4
        log.warning("Deprecated use of get_bool_envvar, use Env.to_bool")

        return Env.to_bool(bool_var, default=False)

    @staticmethod
    @lru_cache(maxsize=None)  # avoid calling it twice for the same var
    def get_bool_from_os(name):
        # Deprecated since 0.7.4
        log.warning("Deprecated use of get_bool_from_os, use Env.get_bool")

        return Env.get_bool(name, default=False)

    def get_connector(self, name):

        service = self.services.get(name)

        if service is None:
            raise AttributeError(f"Service {name} not found")

        if not service.get('available', False):
            raise AttributeError(f"Service {name} is not available")

        connector = service.get('connector')

        if connector is None:
            raise AttributeError(f"Connector {name} is not available")

        return connector

    def get_service_instance(self, service_name, global_instance=True, **kwargs):
        if service_name == AUTH_NAME:
            return self.authentication_instance

        connector = self.get_connector(service_name)

        return connector.get_instance(global_instance=global_instance, **kwargs)

    def load_services(self, path, module):

        main_folder = os.path.join(path, CONNECTORS_FOLDER)
        if not os.path.isdir(main_folder):
            log.debug("Connectors folder not found: {}", main_folder)
            return False

        # Looking for all file in apis folder
        for connector in os.listdir(main_folder):
            connector_path = os.path.join(path, CONNECTORS_FOLDER, connector)
            if not os.path.isdir(connector_path):
                continue
            if connector.startswith("_"):
                continue

            # This is the only exception... we should rename sqlalchemy as alchemy
            if connector == 'sqlalchemy':
                prefix = 'alchemy'
            else:
                prefix = connector

            variables = Detector.load_variables(prefix=prefix)

            if not Env.to_bool(variables.get("enable_connector", True)):
                log.info("{} connector is disabled", connector)
                continue

            # Was this service enabled from the developer?
            enabled = Env.to_bool(variables.get("enable"))
            external = variables.get("external", False)

            self.services.setdefault(connector, {})
            self.services[connector]['available'] = enabled or external

            if not self.services[connector]['available']:
                continue

            log.verbose("Looking for connector class in {}", connector_path)
            connector_module = Meta.get_module_from_string(
                ".".join((module, CONNECTORS_FOLDER, connector))
            )
            classes = Meta.get_new_classes_from_module(connector_module)
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

            # NOTE: module loading algoritm is based on core connectors
            # if you need project connectors with models please review this part
            models_file = os.path.join(connector_path, "models.py")

            if not os.path.isfile(models_file):
                log.verbose("No model found in {}", connector_path)
            else:
                log.debug("Loading models from {}", connector_path)

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

        return True

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

        module_name = f"{BACKEND_PACKAGE}.connectors.{connector}"
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
                connector_instance = ConnectorClass(app)
            except TypeError as e:
                log.exit('Your class {} is not compliant:\n{}', connector_name, e)

            self.services[connector_name]['connector'] = connector_instance

            instances[connector_name] = connector_instance.get_instance()
            ConnectorClass.init_class()

        if self.authentication_service is None:
            log.warning("No authentication service configured")
        elif self.authentication_service not in self.services:
            log.exit("Auth service '{}' is unreachable", self.authentication_service)
        elif not self.services[self.authentication_service].get('available', False):
            log.exit("Auth service '{}' is not available", self.authentication_service)

        if self.authentication_service is not None:
            auth_module = Meta.get_authentication_module(self.authentication_service)
            db = instances[self.authentication_service]
            self.authentication_instance = auth_module.Authentication(db)

            # Only once in a lifetime
            if project_init:

                connector = self.services.get(
                    self.authentication_service).get('connector')
                log.debug("Initializing {}", self.authentication_service)
                connector.initialize()

                with app.app_context():
                    self.authentication_instance.init_users_and_roles()
                    log.info("Initialized authentication module")

                self.project_initialization(instances, app=app)

            if project_clean:
                connector = self.services.get(
                    self.authentication_service).get('connector')
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
            module_path = ".".join((
                CUSTOM_PACKAGE,
                'initialization',
                'initialization',
            ))
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
