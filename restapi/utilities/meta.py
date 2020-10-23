"""
Meta thinking: python objects & introspection

usefull documentation:
http://python-3-patterns-idioms-test.readthedocs.org/en/latest/Metaprogramming.html
"""

import inspect
import pkgutil
from importlib import import_module

from restapi.confs import BACKEND_PACKAGE, CUSTOM_PACKAGE
from restapi.utilities.logs import log


class Meta:
    """Utilities with meta in mind"""

    @staticmethod
    def get_classes_from_module(module):
        """
        Find classes inside a python module file.
        """

        try:
            return {
                name: cls
                for name, cls in module.__dict__.items()
                if isinstance(cls, type)
            }
        except AttributeError:
            log.warning("Could not find any class in module {}", module)

        return {}

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
    def get_module_from_string(modulestring, prefix_package=False, exit_on_fail=False):
        """
        Getting a module import
        when your module is stored as a string in a variable
        """

        if prefix_package:
            modulestring = f"{BACKEND_PACKAGE}.{modulestring.lstrip('.')}"

        try:
            return import_module(modulestring)
        except ModuleNotFoundError as e:
            if exit_on_fail:
                raise e
            # log.warning("Failed to load module:\n{}", e)
        except BaseException as e:
            if exit_on_fail:
                raise e
            log.error("Module {} not found.\nError: {}", modulestring, e)

        return None

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
            cls_attribute = getattr(candidate_as_self, "__class__", None)
            if cls_attribute is not None and inspect.isclass(cls_attribute):
                return args[0]
        return None

    @staticmethod
    def import_models(name, package, exit_on_fail=True):

        if package == BACKEND_PACKAGE:
            module_name = f"{package}.connectors.{name}.models"
        else:
            module_name = f"{package}.models.{name}"

        try:
            module = Meta.get_module_from_string(module_name, exit_on_fail=True)
        except BaseException as e:
            log.error("Cannot load {} models from {}", name, module_name)
            if exit_on_fail:
                log.exit(e)

            log.warning(e)
            return {}

        return Meta.get_new_classes_from_module(module)

    @staticmethod
    def get_authentication_module(auth_service):

        module_name = f"connectors.{auth_service}"
        log.verbose("Loading authentication module: {}", module_name)
        module = Meta.get_module_from_string(
            modulestring=module_name, prefix_package=True, exit_on_fail=True
        )

        return module

    @staticmethod
    def get_celery_tasks(package_name):
        """
        Extract all celery tasks from a module.
        Celery tasks are functions decorated by @celery_app.task(...)
        This decorator transform the function into a class child of
        celery.local.PromiseProxy
        """
        tasks = {}
        # package = tasks folder
        package = Meta.get_module_from_string(package_name)
        if package is None:
            return tasks

        # get all modules in package (i.e. py files)
        for _, module_name, ispkg in pkgutil.iter_modules(package.__path__):
            # skip modules (i.e. subfolders)
            if ispkg:
                continue

            module_path = f"{package_name}.{module_name}"
            log.debug("Loading module '{}'", module_path)

            # convert file name in submodule, i.e.
            # tasks.filename
            submodule = Meta.get_module_from_string(
                module_path,
                exit_on_fail=True,
            )

            # get all functions in py file
            functions = inspect.getmembers(submodule)
            for func in functions:

                obj_type = type(func[1])

                if obj_type.__module__ != "celery.local":
                    continue

                tasks[func[0]] = func[1]
        return tasks

    @staticmethod
    def get_class(module_relpath, class_name):

        abspath = f"{CUSTOM_PACKAGE}.{module_relpath}"

        module = Meta.get_module_from_string(abspath)

        if module is None:
            log.debug("{} path does not exist", abspath)
            return None

        if not hasattr(module, class_name):
            log.verbose("{} not found in {}", class_name, abspath)
            return None

        return getattr(module, class_name)

    @staticmethod
    def get_instance(module_relpath, class_name, **kwargs):

        MyClass = Meta.get_class(module_relpath, class_name)

        if MyClass is None:
            return None

        try:
            return MyClass(**kwargs)
        except BaseException as e:  # pragma: no cover
            log.error("Errors loading {}.{}: {}", module_relpath, class_name, e)
            return None
