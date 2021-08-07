import abc
from typing import Tuple

from flask import Flask

from restapi.connectors import Connector
from restapi.rest.definition import EndpointResource
from restapi.services.authentication import User
from restapi.types import FlaskRequest, Props

FlaskApp = Flask


class BaseCustomizer(metaclass=abc.ABCMeta):

    # These are scopes used in get_custom_input_fields
    ADMIN = 1
    PROFILE = 2
    REGISTRATION = 3

    @staticmethod
    @abc.abstractmethod
    def custom_user_properties_pre(
        properties: Props,
    ) -> Tuple[Props, Props]:  # pragma: no cover
        """
        executed just before user creation
        use this method to removed or manipulate input properties
        before sending to the database
        """
        return properties, {}

    @staticmethod
    @abc.abstractmethod
    def custom_user_properties_post(
        user: User, properties: Props, extra_properties: Props, db: Connector
    ) -> None:  # pragma: no cover
        """
        executed just after user creation
        use this method to implement extra operation needed to create a user
        e.g. store additional relationships
        """
        pass

    @staticmethod
    @abc.abstractmethod
    def manipulate_profile(
        ref: EndpointResource, user: User, data: Props
    ) -> Props:  # pragma: no cover
        """
        execute before sending data from the profile endpoint
        use this method to add additonal information to the user profile
        """
        return data

    @staticmethod
    @abc.abstractmethod
    def get_custom_input_fields(
        request: FlaskRequest, scope: int
    ) -> Props:  # pragma: no cover

        # required = request and request.method == "POST"
        """
        if scope == BaseCustomizer.ADMIN:
            return {
                'custom_field': fields.Int(
                    required=required,
                    # validate=validate.Range(min=0, max=???),
                    validate=validate.Range(min=0),
                    label="CustomField",
                    description="This is a custom field",
                )
            }
        # these are editable fields in profile
        if scope == BaseCustomizer.PROFILE:
            return {}

        # these are additional fields in registration form
        if scope == BaseCustomizer.REGISTRATION:
            return {}
        """
        return {}

    @staticmethod
    @abc.abstractmethod
    def get_custom_output_fields(request: FlaskRequest) -> Props:  # pragma: no cover
        """
        this method is used to extend the output model of admin users
        """

        return {}
