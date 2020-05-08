# -*- coding: utf-8 -*-

"""
Meta thinking: python objects & introspection

usefull documentation:
http://python-3-patterns-idioms-test.readthedocs.org/en/latest/Metaprogramming.html
"""

import pkgutil
import inspect
from importlib import import_module
from restapi.confs import BACKEND_PACKAGE, CUSTOM_PACKAGE
from restapi.utilities.logs import log


class Meta:
    """Utilities with meta in mind"""

    def __init__(self):
        # Deprecated since 0.7.3
        log.warning("Deprecated initialization of Meta package")

    @staticmethod
    def get_submodules_from_package(package):
        submodules = []
        if package is None:
            return submodules
        for _, modname, ispkg in pkgutil.iter_modules(package.__path__):
            if not ispkg:
                submodules.append(modname)
        return submodules

    @staticmethod
    def get_classes_from_module(module):
        """
        Find classes inside a python module file.
        """

        classes = {}
        try:
            classes = dict(
                [
                    (name, cls)
                    for name, cls in module.__dict__.items()
                    if isinstance(cls, type)
                ]
            )
        except AttributeError:
            log.warning("Could not find any class in module {}", module)

        return classes

    @staticmethod
    def get_new_classes_from_module(module):
        """
        Skip classes not originated inside the module.
        """

        classes = {}
        for key, value in Meta.get_classes_from_module(module).items():
            if module.__name__ in value.__module__:
                classes[key] = value
        return classes

    @staticmethod
    def get_module_from_string(
        modulestring,
        prefix_package=False,
        exit_if_not_found=False,
        exit_on_fail=False
    ):
        """
        Getting a module import
        when your module is stored as a string in a variable
        """

        module = None
        if prefix_package:
            modulestring = BACKEND_PACKAGE + '.' + modulestring.lstrip('.')

        try:
            # Meta language for dinamically import
            module = import_module(modulestring)
        except ModuleNotFoundError as e:  # pylint:disable=catching-non-exception
            if exit_on_fail:
                raise e
            elif exit_if_not_found:
                log.exit("Failed to load module:\n{}", e)
            # else:
            #     log.warning("Failed to load module:\n{}", e)
        except BaseException as e:
            if exit_on_fail:
                raise e
            else:
                log.error("Module {} not found.\nError: {}", modulestring, e)

        return module

    @staticmethod
    def import_submodules_from_package(
        package_name, exit_if_not_found=False, exit_on_fail=False
    ):

        submodules = []
        package = Meta.get_module_from_string(package_name)

        for module_name in Meta.get_submodules_from_package(package):
            module_path = package_name + '.' + module_name
            log.debug("Loading module '{}'", module_path)

            submod = Meta.get_module_from_string(
                module_path,
                exit_if_not_found=exit_if_not_found,
                exit_on_fail=exit_on_fail,
            )
            submodules.append(submod)
        return submodules

    @staticmethod
    def get_class_from_string(classname, module, skip_error=False):
        """ Get a specific class from a module using a string variable """

        myclass = None
        try:
            # Meta language for dinamically import
            myclass = getattr(module, classname)
        except AttributeError as e:
            if not skip_error:
                log.critical("Failed to load class from module: " + str(e))
            else:
                pass

        return myclass

    @staticmethod
    def get_self_reference_from_args(*args):
        """
        Useful in decorators:
        being able to call the internal method by getting
        the 'self' reference from the decorated method
        (when it's there)
        """

        if len(args) > 0:
            candidate_as_self = args[0]
            cls_attribute = getattr(candidate_as_self, '__class__', None)
            if cls_attribute is not None and inspect.isclass(cls_attribute):
                return args[0]
        return None

    @staticmethod
    def obj_from_models(obj_name, module_name, package):
        module_name = "{}.models.{}".format(package, module_name)
        module = Meta.get_module_from_string(module_name, exit_on_fail=True)

        obj = getattr(module, obj_name, None)
        return obj

    @staticmethod
    def import_models(name, package, exit_on_fail=True):

        models = {}
        module_name = "{}.models.{}".format(package, name)
        try:
            module = Meta.get_module_from_string(module_name, exit_on_fail=True)
        except BaseException as e:
            log.error("Cannot load {} models")
            if exit_on_fail:
                log.exit(e)

            log.warning(e)
            return {}

        models = Meta.get_new_classes_from_module(module)

        return models

    @staticmethod
    def get_authentication_module(auth_service):

        module_name = "services.authentication.{}".format(auth_service)
        log.verbose("Loading authentication module: {}", module_name)
        module = Meta.get_module_from_string(
            modulestring=module_name, prefix_package=True, exit_on_fail=True
        )

        return module

    @staticmethod
    def get_celery_tasks_from_module(submodule):
        """
            Extract all celery tasks from a module.
            Celery tasks are functions decorated by @celery_app.task(...)
            This decorator transform the function into a class child of
            celery.local.PromiseProxy
        """
        tasks = {}
        functions = inspect.getmembers(submodule)
        for func in functions:

            obj_type = type(func[1])

            if obj_type.__module__ != "celery.local":
                continue

            tasks[func[0]] = func[1]
        return tasks

    @staticmethod
    def get_customizer_class(module_relpath, class_name, args=None):

        abspath = "{}.{}".format(CUSTOM_PACKAGE, module_relpath)
        MyClass = Meta.get_class_from_string(
            class_name,
            Meta.get_module_from_string(abspath),
            skip_error=True,
        )

        instance = None
        if args is None:
            args = {}

        if MyClass is None:
            log.verbose("No customizer available for {}", class_name)
        else:
            try:
                instance = MyClass(**args)
            except BaseException as e:
                log.error("Errors during customizer: {}", e)
            else:
                log.debug("Customizer called: {}", class_name)
        return instance
