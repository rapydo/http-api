# -*- coding: utf-8 -*-

"""
The most basic (and standard) Rest Resource
we could provide back then
"""

import pytz
import dateutil.parser
from datetime import datetime
from injector import inject
from flask_restful import request, Resource, reqparse
from jsonschema.exceptions import ValidationError
from restapi.confs import API_URL
from restapi.exceptions import RestApiException
from restapi.rest.response import ResponseElements
from restapi.swagger import input_validation
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.globals import mem
from restapi.utilities.time import string_from_timestamp
from restapi.services.detect import detector
from restapi.utilities.logs import log, obfuscate_dict

###################
# Paging costants
CURRENTPAGE_KEY = 'currentpage'
DEFAULT_CURRENTPAGE = 1
PERPAGE_KEY = 'perpage'
DEFAULT_PERPAGE = 10


###################
# Extending the concept of rest generic resource
class EndpointResource(Resource):

    baseuri = API_URL
    labels = []
    depends_on = []
    expose_schema = False
    publish = True
    labels = ["undefined"]
    """
    Implements a generic Resource for our Restful APIs model
    """

    @inject(**detector.services_classes)
    def __init__(self, **services):

        if len(services) < 1:
            raise AttributeError("No services available for requests...")

        # Init original class
        super(EndpointResource, self).__init__()

        self.services = services
        self.load_authentication()
        self.init_parameters()

        # Custom init
        custom_method = getattr(self, 'custom_init', None)
        if custom_method is not None:
            custom_method()

    def myname(self):
        return self.__class__.__name__

    def load_authentication(self):
        # Authentication instance is always needed at each request
        self.auth = self.get_service_instance(
            detector.authentication_name, authenticator=True
        )
        auth_backend = self.get_service_instance(detector.authentication_service)
        self.auth.db = auth_backend

        # Set parameters to be used

    def get_service_instance(self, service_name, global_instance=True, **kwargs):
        farm = self.services.get(service_name)
        if farm is None:
            raise AttributeError("Service {} not found".format(service_name))
        instance = farm.get_instance(global_instance=global_instance, **kwargs)
        return instance

    def init_parameters(self):
        # Make sure you can parse arguments at every call
        self._args = {}
        self._json_args = {}
        self._params = {}

        # Query parameters
        self._parser = reqparse.RequestParser()

        # use self to get the classname
        classname = self.myname()
        # use request to recover uri and method
        uri = str(request.url_rule)
        method = request.method.lower()

        # FIXME: this works only for 'query' parameters
        # recover from the global mem parameters query parameters
        current_params = (
            mem.customizer._query_params.get(classname, {}).get(uri, {}).get(method, {})
        )

        if len(current_params) > 0:

            # Basic options
            basevalue = str  # Python3
            # basevalue = unicode  #Python2
            act = 'store'  # store is normal, append is a list
            loc = ['headers', 'values']  # multiple locations
            trim = True

            for param, data in current_params.items():

                # FIXME: Add a method to convert types swagger <-> flask
                tmptype = data.get('type', 'string')
                if tmptype == 'boolean':
                    mytype = bool
                if tmptype == 'number':
                    mytype = int
                else:
                    mytype = basevalue

                # TO CHECK: I am creating an option to handle arrays
                if tmptype == 'select':
                    act = 'append'

                self._parser.add_argument(
                    param,
                    type=mytype,
                    default=data.get('default', None),
                    required=data.get('required', False),
                    trim=trim,
                    action=act,
                    location=loc,
                )
                log.verbose("Accept param '{}' type {}", param, mytype)

        # TODO: should I check body parameters?

    @staticmethod
    def clean_parameter(param=""):
        """ I get parameters already with '"' quotes from curl? """
        if param is None:
            return param
        return param.strip('"')

    def parse(self):
        """
        Parameters may be necessary at any method: Parse them all.
        """

        self._args = self._parser.parse_args()
        return self._args

    def get_input(self, forcing=True, single_parameter=None, default=None):
        """
        Recover parameters from current requests.

        Note that we talk about JSON only when having a PUT method,
        while there is URL encoding for GET, DELETE
        and Headers encoding with POST.

        Non-JSON Parameters are already parsed at this point,
        while JSON parameters may be already saved from another previous call
        """

        self.parse()
        # TODO: study how to apply types in swagger not only for query params
        # so we can use them for validation

        # if is an upload in streaming, I must not consume
        # request.data or request.json, otherwise it get lost
        if len(self._json_args) < 1 and request.mimetype != 'application/octet-stream':
            try:
                self._json_args = request.get_json(force=forcing)
            except Exception:  # as e:
                pass

            # json payload and formData cannot co-exist
            if len(self._json_args) < 1:
                self._json_args = request.form

            # NOTE: if JSON all parameters are just string at the moment...
            for key, value in self._json_args.items():

                if value is None:
                    continue
                # TODO: remove and check
                # how to fix the `request.form` emptiness

                if key in self._args and self._args[key] is not None:
                    key += '_json'
                self._args[key] = value

        if single_parameter is not None:
            return self._args.get(single_parameter, default)

        if len(self._args) > 0:
            log.verbose("Parameters {}", obfuscate_dict(self._args))
        return self._args

    def set_method_id(self, name='myid', idtype='string'):
        """ How to have api/method/:id route possible"""
        self.endtype = idtype + ':' + name

    def get_paging(self, force_read_parameters=False):

        if force_read_parameters:
            self.get_input()
        # NOTE: you have to call self.get_input prior to use this method
        limit = self._args.get(PERPAGE_KEY, DEFAULT_PERPAGE)
        current_page = self._args.get(CURRENTPAGE_KEY, DEFAULT_CURRENTPAGE)

        if limit is None:
            limit = DEFAULT_PERPAGE
        if current_page is None:
            current_page = DEFAULT_CURRENTPAGE

        try:
            limit = int(limit)
        except ValueError:
            log.warning("{} is expected to be an int, not {}", PERPAGE_KEY, limit)
            limit = DEFAULT_PERPAGE

        try:
            current_page = int(current_page)
        except ValueError:
            log.warning(
                "{} is expected to be an int, not {}", CURRENTPAGE_KEY, current_page
            )
            current_page = DEFAULT_CURRENTPAGE

        return (current_page, limit)

    def get_input_properties(self):
        """
        NOTE: usefull to use for swagger validation?
        """

        # get body definition name
        parameters = self.get_endpoint_custom_definition().copy()
        parameter = parameters.pop()
        ref = parameter.get('schema', {}).get('$ref')
        refname = ref.split('/').pop()
        # get body definition properties
        definitions = mem.customizer._definitions.get('definitions')
        return definitions.get(refname).get('properties')

    def explode_response(
        self,
        api_output,
        get_all=False,
        get_error=False,
        get_status=False,
        get_meta=False,
    ):

        from restapi.rest.response import get_content_from_response

        content, err, meta, code = get_content_from_response(api_output)

        if get_error:
            return err
        elif get_meta:
            return meta
        elif get_status:
            return code
        elif get_all:
            return content, err, code

        return content

    def get_current_user(self):
        """
        Return the associated User OBJECT if:
        - the endpoint requires authentication
        - a valid token was provided
        in the current endpoint call.

        Note: this method works because of actions inside
        authentication/__init__.py@verify_token method
        """

        return self.auth.get_user()

    # def method_not_allowed(self, methods=['GET']):
    #     methods.append('HEAD')
    #     methods.append('OPTIONS')
    #     methods_string = ""
    #     for method in methods:
    #         methods_string += method + ', '
    #     return self.force_response(
    #         headers={'ALLOW': methods_string.strip(', ')},
    #         errors='The method is not allowed for the requested URL.',
    #         code=hcodes.HTTP_BAD_METHOD_NOT_ALLOWED)

    def force_response(self, *args, **kwargs):
        """
        Helper function to let the developer define
        how to respond with the REST and HTTP protocol

        Build a ResponseElements instance.
        """
        # If args has something, it should be one simple element
        # That element is the content and nothing else
        if isinstance(args, tuple) and len(args) > 0:
            kwargs['defined_content'] = args[0]
        elif 'defined_content' not in kwargs:
            kwargs['defined_content'] = None

        # try to push keywords arguments directly to the attrs class
        response = None
        try:
            response = ResponseElements(**kwargs)
        except Exception as e:
            response = ResponseElements(errors=str(e))
        return response

    def empty_response(self):
        """ Empty response as defined by the protocol """
        return self.force_response("", code=hcodes.HTTP_OK_NORESPONSE)

    def send_warnings(self, defined_content, errors, code=None, head_method=False):
        """
        Warnings when there is both data and errors in response.
        So 'defined_content' and 'errors' are required,
        while the code has to be between below 400
        """
        if code is None or code >= hcodes.HTTP_BAD_REQUEST:
            code = hcodes.HTTP_MULTIPLE_CHOICES

        if head_method:
            defined_content = None
            errors = None

        return self.force_response(
            defined_content=defined_content,
            errors=errors,
            code=code,
            head_method=head_method,
        )

    def send_errors(
        self, message=None, errors=None, code=None, headers=None, head_method=False
    ):
        """ Setup an error message """

        if errors is None:
            errors = []
        if isinstance(errors, str):
            errors = [errors]

        # See if we have the main message
        if message is not None:
            errors.append(message)

        if code is None or code < hcodes.HTTP_BAD_REQUEST:
            # default error
            code = hcodes.HTTP_SERVER_ERROR

        if errors is not None and len(errors) > 0:
            log.error(errors)

        if head_method:
            errors = None

        return self.force_response(
            errors=errors, code=code, headers=headers, head_method=head_method
        )

    def report_generic_error(self, message=None, current_response_available=True):

        if message is None:
            message = "Something BAD happened somewhere..."
        log.critical(message)

        user_message = "Server unable to respond."
        code = hcodes.HTTP_SERVER_ERROR
        if current_response_available:
            return self.force_response(errors=user_message, code=code)
        else:
            # flask-like
            return (user_message, code)

    def send_credentials(self, token, extra=None, meta=None):
        """
        Define a standard response to give a Bearer token back.
        Also considering headers.
        """
        # TODO: write it and use it in EUDAT
        return NotImplementedError("To be written")

    def formatJsonResponse(self, instances, resource_type=None):
        """
        Format specifications can be found here:
        http://jsonapi.org
        """

        json_data = {}
        endpoint = request.url
        json_data["links"] = {"self": endpoint, "next": None, "last": None}

        json_data["content"] = []
        if not isinstance(instances, list):
            raise AttributeError("Expecting a list of objects to format")
        if len(instances) < 1:
            return json_data

        for instance in instances:
            json_data["content"].append(self.getJsonResponse(instance))

        # FIXME: get pages FROM SELF ARGS?
        # json_data["links"]["next"] = \
        #     endpoint + '?currentpage=2&perpage=1',
        # json_data["links"]["last"] = \
        #     endpoint + '?currentpage=' + str(len(instances)) + '&perpage=1',

        return json_data

    def get_show_fields(self, obj, function_name, view_public_only, fields=None):
        if fields is None:
            fields = []
        if len(fields) < 1:
            if hasattr(obj, function_name):
                fn = getattr(obj, function_name)
                fields = fn(view_public_only=view_public_only)

        verify_attribute = hasattr
        if isinstance(obj, dict):
            verify_attribute = dict.get

        attributes = {}
        for key in fields:
            if verify_attribute(obj, key):
                get_attribute = getattr
                if isinstance(obj, dict):
                    get_attribute = dict.get

                attribute = get_attribute(obj, key)
                # datetime is not json serializable,
                # converting it to string
                # FIXME: use flask.jsonify
                if attribute is None:
                    attributes[key] = None
                elif isinstance(attribute, datetime):
                    dval = string_from_timestamp(attribute.strftime('%s'))
                    attributes[key] = dval
                else:

                    # Based on neomodel choices:
                    # http://neomodel.readthedocs.io/en/latest/properties.html#choices
                    choice_function = "get_{}_display".format(key)
                    if hasattr(obj, choice_function):
                        fn = getattr(obj, choice_function)
                        description = fn()

                        attribute = {"key": attribute, "description": description}
                    attributes[key] = attribute

        return attributes

    def getJsonResponse(
        self,
        instance,
        fields=None,
        resource_type=None,
        skip_missing_ids=False,
        view_public_only=False,
        relationship_depth=0,
        max_relationship_depth=1,
        relationship_name="",
        relationships_expansion=None,
    ):
        """
        Lots of meta introspection to guess the JSON specifications
        Very important: this method only works with customized neo4j models
        """

        if resource_type is None:
            resource_type = type(instance).__name__.lower()

        # Get id
        verify_attribute = hasattr
        if isinstance(instance, dict):
            verify_attribute = dict.get
        if verify_attribute(instance, "uuid"):
            id = str(instance.uuid)
        elif verify_attribute(instance, "id"):
            id = str(instance.id)
        else:
            id = "-"

        if id is None:
            id = "-"

        data = {
            "id": id,
            "type": resource_type,
            "attributes": {}
            # "links": {"self": request.url + '/' + id},
        }

        if skip_missing_ids and id == '-':
            del data['id']

        # TO FIX: for now is difficult to compute self links for relationships
        if relationship_depth == 0:
            self_uri = request.url
            if not self_uri.endswith(id):
                self_uri += '/' + id
            data["links"] = {"self": self_uri}

        data["attributes"] = self.get_show_fields(
            instance, 'show_fields', view_public_only, fields
        )

        # Relationships
        max_depth_reached = relationship_depth >= max_relationship_depth

        relationships = []
        if not max_depth_reached:

            function_name = 'follow_relationships'
            if hasattr(instance, function_name):
                fn = getattr(instance, function_name)
                relationships = fn(view_public_only=view_public_only)

            else:

                if view_public_only:
                    field_name = '_public_relationships_to_follow'
                else:
                    field_name = '_relationships_to_follow'

                if hasattr(instance, field_name):
                    log.warning("Obsolete use of {} into models", field_name)
                    relationships = getattr(instance, field_name)
        elif relationships_expansion is not None:
            for e in relationships_expansion:
                if e.startswith("{}.".format(relationship_name)):
                    rel_name_len = len(relationship_name) + 1
                    expansion_rel = e[rel_name_len:]
                    log.debug(
                        "Expanding {} relationship with {}",
                        relationship_name,
                        expansion_rel,
                    )
                    relationships.append(expansion_rel)

        linked = {}
        for relationship in relationships:
            subrelationship = []

            if not hasattr(instance, relationship):
                continue
            rel = getattr(instance, relationship)
            for node in rel.all():
                if relationship_name == "":
                    rel_name = relationship
                else:
                    rel_name = "{}.{}".format(relationship_name, relationship)
                subnode = self.getJsonResponse(
                    node,
                    view_public_only=view_public_only,
                    skip_missing_ids=skip_missing_ids,
                    relationship_depth=relationship_depth + 1,
                    max_relationship_depth=max_relationship_depth,
                    relationship_name=rel_name,
                    relationships_expansion=relationships_expansion,
                )

                # Verify if instance and node are linked by a
                # relationship with a custom model with fields flagged
                # as show=True. In this case, append relationship
                # properties to the attribute model of the node
                r = rel.relationship(node)
                attrs = self.get_show_fields(r, 'show_fields', view_public_only)

                for k in attrs:
                    if k in subnode['attributes']:
                        log.warning(
                            "Name collision {} on node {}, model {}, property model={}",
                            k, subnode, type(node), type(r)
                        )
                    subnode['attributes'][k] = attrs[k]

                # subnode['attributes']['pippo'] = 'boh'
                subrelationship.append(subnode)

            if len(subrelationship) > 0:
                linked[relationship] = subrelationship

        if len(linked) > 0:
            data['relationships'] = linked

        return data

    def getJsonResponseFromSql(self, instance):

        resource_type = type(instance).__name__.lower()

        # Get id
        verify_attribute = hasattr
        if isinstance(instance, dict):
            verify_attribute = dict.get
        if verify_attribute(instance, "uuid"):
            id = str(instance.uuid)
        elif verify_attribute(instance, "id"):
            id = str(instance.id)
        else:
            id = "-"

        if id is None:
            id = "-"

        data = {
            "id": id,
            "type": resource_type,
            "attributes": {}
            # "links": {"self": request.url + '/' + id},
        }
        for c in instance.__table__.columns._data:
            if c == 'password':
                continue

            data["attributes"][c] = getattr(instance, c)

        return data

    def getJsonResponseFromMongo(self, instance):

        resource_type = type(instance).__name__.lower()

        # Get id
        verify_attribute = hasattr
        if isinstance(instance, dict):
            verify_attribute = dict.get
        if verify_attribute(instance, "uuid"):
            id = str(instance.uuid)
        elif verify_attribute(instance, "id"):
            id = str(instance.id)
        else:
            id = "-"

        if id is None:
            id = "-"

        data = {
            "id": id,
            "type": resource_type,
            "attributes": {}
            # "links": {"self": request.url + '/' + id},
        }
        # log.critical(instance._data._members)
        for c in instance._data._members:
            if c == 'password':
                continue

            attribute = getattr(instance, c)

            if isinstance(attribute, list):
                continue

            data["attributes"][c] = attribute

        return data

    def get_endpoint_definition(self, key=None, is_schema_url=False, method=None):

        url = request.url_rule.rule
        if is_schema_url:
            url = mem.customizer._schemas_map[url]

        if url not in mem.customizer._definitions["paths"]:
            return None

        if method is None:
            method = request.method
        method = method.lower()
        if method not in mem.customizer._definitions["paths"][url]:
            return None

        tmp = mem.customizer._definitions["paths"][url][method]

        if key is None:
            return tmp
        if key not in tmp:
            return None

        return tmp[key]

    def get_endpoint_custom_definition(self, is_schema_url=False, method=None):
        url = request.url_rule.rule
        if is_schema_url:
            url = mem.customizer._schemas_map[url]

        if method is None:
            method = request.method
        method = method.lower()

        if url not in mem.customizer._parameter_schemas:
            raise RestApiException(
                "No parameters schema defined for {}".format(url),
                status_code=hcodes.HTTP_BAD_NOTFOUND,
            )
        if method not in mem.customizer._parameter_schemas[url]:
            raise RestApiException(
                "No parameters schema defined for method {} in {}".format(method, url),
                status_code=hcodes.HTTP_BAD_NOTFOUND,
            )
            return None
        return mem.customizer._parameter_schemas[url][method]

    # HANDLE INPUT PARAMETERS
    def read_properties(self, schema, values, checkRequired=True):

        properties = {}
        for field in schema:
            if 'custom' in field:
                if 'islink' in field['custom']:
                    if field['custom']['islink']:
                        continue

            k = field["name"]
            if k in values:
                properties[k] = values[k]

            # this field is missing but required!
            elif checkRequired and field["required"]:
                raise RestApiException(
                    'Missing field: {}'.format(k), status_code=hcodes.HTTP_BAD_REQUEST
                )

        return properties

    def update_properties(self, instance, schema, properties):

        for field in schema:
            if 'custom' in field:
                if 'islink' in field['custom']:
                    if field['custom']['islink']:
                        continue
            key = field["name"]

            if key in properties:
                instance.__dict__[key] = properties[key]

    def update_sql_properties(self, instance, schema, properties):

        for field in schema:
            if 'custom' in field:
                if 'islink' in field['custom']:
                    if field['custom']['islink']:
                        continue
            key = field["name"]

            from sqlalchemy.orm.attributes import set_attribute
            if key in properties:
                set_attribute(instance, key, properties[key])

    def update_mongo_properties(self, instance, schema, properties):

        for field in schema:
            if 'custom' in field:
                if 'islink' in field['custom']:
                    if field['custom']['islink']:
                        continue
            key = field["name"]

            if key in properties:
                setattr(instance, key, properties[key])

    def parseAutocomplete(self, properties, key, id_key='value', split_char=None):
        value = properties.get(key, None)

        ids = []

        if value is None:
            return ids

        # Multiple autocomplete
        if type(value) is list:
            for v in value:
                if v is None:
                    return None
                if id_key in v:
                    ids.append(v[id_key])
                else:
                    ids.append(v)
            return ids

        # Single autocomplete
        if id_key in value:
            return [value[id_key]]

        # Command line input
        if split_char is None:
            return [value]

        return value.split(split_char)

    def get_roles(self, properties):

        roles = []
        ids = self.parseAutocomplete(properties, 'roles', id_key='name', split_char=',')

        if ids is None:
            return roles

        return ids

    def get_user_if_logged(self):
        """
        Helper to be used inside an endpoint that doesn't explicitly
        ask for authentication, but might want to do some extra behaviour
        when a valid token is presented
        """

        user = self.auth.get_user()
        if user is not None:
            return user

        if request.method == 'OPTIONS':
            return user

        from restapi.protocols.bearer import HTTPTokenAuth

        http = HTTPTokenAuth()
        auth_type, token = http.get_authorization_token()

        if auth_type is not None:
            if http.authenticate(self.auth.verify_token, token):
                # we have a valid token in header
                user = self.get_current_user()
                log.debug("Logged user: {}", user.email)

        return user

    # this is a simple wrapper of restapi.swagger.input_validation
    def validate_input(self, json_parameters, definitionName):

        try:
            return input_validation(json_parameters, definitionName)
        except ValidationError as e:
            raise RestApiException(e.message, status_code=hcodes.HTTP_BAD_REQUEST)
