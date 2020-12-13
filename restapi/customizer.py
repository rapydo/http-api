import abc


class BaseCustomizer(metaclass=abc.ABCMeta):

    # These are scopes used in get_custom_input_fields
    ADMIN = 1
    PROFILE = 2
    REGISTRATION = 3

    @abc.abstractmethod
    def custom_user_properties_pre(properties):  # pragma: no cover
        """
        executed just before user creation
        use this method to removed or manipulate input properties
        before sending to the database
        """
        return properties, {}

    @abc.abstractmethod
    def custom_user_properties_post(
        user, properties, extra_properties, db
    ):  # pragma: no cover
        """
        executed just after user creation
        use this method to implement extra operation needed to create a user
        e.g. store additional relationships
        """
        pass

    @abc.abstractmethod
    def manipulate_profile(ref, user, data):  # pragma: no cover
        """
        execute before sending data from the profile endpoint
        use this method to add additonal information to the user profile
        """
        return data

    @abc.abstractmethod
    def get_custom_input_fields(request, scope):  # pragma: no cover

        # required = request and request.method == "POST"
        """
        if scope == BaseCustomizer.ADMIN:
            return {
                'custom_field': fields.Int(
                    required=required,
                    # validate=validate.Range(min=0, max=???),
                    validate=validate.Range(min=0),
                    label="CustomField",
                    description="This is a custom field"
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

    @abc.abstractmethod
    def get_custom_output_fields(request):  # pragma: no cover
        """
        this method is used to extend the output model of admin users
        """

        # required = request and request.method == "POST"
        """
        return {
            'custom_field': fields.Int(
                required=required,
                # validate=validate.Range(min=0, max=???),
                validate=validate.Range(min=0),
                label="CustomField",
                description="This is a custom field"
            )
        }
        """
        return {}
