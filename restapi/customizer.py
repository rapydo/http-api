import abc


class BaseCustomizer(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def custom_user_properties_pre(properties):  # pragma: no cover
        # executed just before user creation
        # use this to removed or manipulate input properties before sending to the db
        return properties, {}

    @abc.abstractmethod
    def custom_user_properties_post(
        user, properties, extra_properties, db
    ):  # pragma: no cover
        # executed just after user creation
        # use this to implement extra operation in user creation
        # e.g. store additional relationships
        pass

    @abc.abstractmethod
    def manipulate_profile(ref, user, data):  # pragma: no cover
        # data['CustomField'] = user.custom_field

        return data

    @abc.abstractmethod
    def get_user_editable_fields(request):  # pragma: no cover
        # return custom fields or a part of them
        return {}

    @abc.abstractmethod
    def get_custom_input_fields(request):  # pragma: no cover

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

    @abc.abstractmethod
    def get_custom_output_fields(request):  # pragma: no cover

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
