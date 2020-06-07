import os
from functools import lru_cache


class Env:
    @staticmethod
    @lru_cache
    def get(var, default=None):
        return os.getenv(var, default)

    @staticmethod
    @lru_cache
    def get_bool(var, default=False):
        value = Env.get(var, default)
        return Env.to_bool(value, default)

    @staticmethod
    @lru_cache
    def get_int(var, default=0):
        value = Env.get(var, default)
        return Env.to_int(value, default)

    @staticmethod
    @lru_cache
    def to_bool(var, default=False):

        if var is None:
            return default

        if isinstance(var, bool):
            return var

        # if not directly a bool, try an interpretation
        # INTEGERS
        try:
            tmp = int(var)
            return bool(tmp)
        except (TypeError, ValueError):
            pass

        # STRINGS
        if isinstance(var, str):
            # false / False / FALSE
            if var.lower() == "false":
                return False
            # any non empty string has to be considered True
            if len(var) > 0:
                return True

        return default

    @staticmethod
    @lru_cache
    def to_int(var, default=0):

        if var is None:
            return default

        if isinstance(var, int):
            return var

        try:
            return int(var)
        except ValueError:
            pass

        return default

    @staticmethod
    def load_group(label):

        variables = {}
        for var, value in os.environ.items():
            var = var.lower()
            if var.startswith(label):
                key = var[len(label) :].strip("_")
                value = value.strip('"').strip("'")
                variables[key] = value
        return variables
