import abc


class BaseCustomizer(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def custom_user_properties_pre(self, properties):  # pragma: no cover
        # executed just before user creation
        # use this to removed or manipulate input properties before sending to the db
        return properties, {}

    @abc.abstractmethod
    def custom_user_properties_post(
        self, user, properties, extra_properties, db
    ):  # pragma: no cover
        # executed just after user creation
        # use this to implement extra operation in user creation
        # e.g. store additional relationships
        pass
