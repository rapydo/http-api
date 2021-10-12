"""
Meta thinking: python objects & introspection

usefull documentation:
http://python-3-patterns-idioms-test.readthedocs.org/en/latest/Metaprogramming.html
"""

import inspect
import pkgutil
from importlib import import_module
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Type

from restapi.config import BACKEND_PACKAGE, CUSTOM_PACKAGE
from restapi.utilities import print_and_exit
from restapi.utilities.logs import log


class Meta:
    """Utilities with meta in mind"""

    @staticmethod
    def get_classes_from_module(module: ModuleType) -> Dict[str, Type[Any]]:
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
    def get_new_classes_from_module(module: ModuleType) -> Dict[str, Type[Any]]:
        """
        Skip classes not originated inside the module.
        """

        classes = {}
        for name, value in Meta.get_classes_from_module(module).items():
            if module.__name__ in value.__module__:
                classes[name] = value
        return classes

    # Should return `from types import ModuleType` -> Optional[ModuleType]
    @staticmethod
    def get_module_from_string(
        modulestring: str, exit_on_fail: bool = False
    ) -> Optional[ModuleType]:
        """
        Getting a module import
        when your module is stored as a string in a variable
        """

        try:
            return import_module(modulestring)
        except ModuleNotFoundError as e:
            if exit_on_fail:
                log.error(e)
                raise e
            return None
        except Exception as e:  # pragma: no cover
            if exit_on_fail:
                log.error(e)
                raise e
            log.error("Module {} not found.\nError: {}", modulestring, e)

            return None

    @staticmethod
    def get_self_reference_from_args(*args: Any) -> Optional[Any]:
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
    def import_models(
        name: str, package: str, mandatory: bool = False
    ) -> Dict[str, Type[Any]]:

        if package == BACKEND_PACKAGE:
            module_name = f"{package}.connectors.{name}.models"
        else:
            module_name = f"{package}.models.{name}"

        try:
            module = Meta.get_module_from_string(module_name, exit_on_fail=True)
        except Exception as e:
            module = None
            if mandatory:
                log.critical(e)

        if not module:
            if mandatory:
                print_and_exit("Cannot load {} models from {}", name, module_name)

            return {}

        return Meta.get_new_classes_from_module(module)

    @staticmethod
    def get_celery_tasks(package_name: str) -> List[Callable[..., Any]]:
        """
        Extract all celery tasks from a module.
        Celery tasks are functions decorated by @CeleryExt.celery_app.task(...)
        This decorator transform the function into a class child of
        celery.local.PromiseProxy
        """
        tasks: List[Callable[..., Any]] = []
        # package = tasks folder
        package = Meta.get_module_from_string(package_name)
        if package is None:
            return tasks

        # get all modules in package (i.e. py files)
        # my-py does not like accessing __path__
        path = package.__path__  # type: ignore
        for _, module_name, ispkg in pkgutil.iter_modules(path):
            # skip modules (i.e. subfolders)
            if ispkg:  # pragma: no cover
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

                # This was a dict name => func
                # tasks[func[0]] = func[1]
                # Now it is a list
                tasks.append(func[1])
        return tasks

    @staticmethod
    def get_class(module_relpath: str, class_name: str) -> Optional[Any]:

        abspath = f"{CUSTOM_PACKAGE}.{module_relpath}"

        module = Meta.get_module_from_string(abspath)

        if module is None:
            log.debug("{} path does not exist", abspath)
            return None

        if not hasattr(module, class_name):
            return None

        return getattr(module, class_name)
