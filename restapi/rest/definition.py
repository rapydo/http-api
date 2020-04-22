# -*- coding: utf-8 -*-

"""
The most basic (and standard) Rest Resource
we could provide back then
"""

from datetime import datetime
from flask import make_response
from flask_restful import request, Resource, reqparse
from flask_apispec import MethodResource
from jsonschema.exceptions import ValidationError
from typing import List, Dict
from neomodel import StructuredNode

from restapi.confs import API_URL, WRAP_RESPONSE
from restapi.exceptions import RestApiException
from restapi.rest.response import ResponseMaker
from restapi.swagger import input_validation
from restapi.services.authentication.bearer import HTTPTokenAuth
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
    # labels = []
    depends_on = []
    expose_schema = False
    publish = True
    labels = ["undefined"]
    """
    Implements a generic Resource for our Restful APIs model
    """

    def __init__(self):
        super(EndpointResource, self).__init__()

        self.auth = self.load_authentication()
        try:
            self.init_parameters()
        except RuntimeError:
            # Once converted everything to FastApi remove this init_parameters
            # Find other warning like this by searching:
            # **FASTAPI**
            # log.warning(
            #     "self.init_parameters should be removed since handle by webargs")
            pass

        # Custom init
        if hasattr(self, 'custom_init'):
            self.custom_init()

    def myname(self):
        return self.__class__.__name__

    @staticmethod
    def load_authentication():
        # Authentication instance is always needed at each request
        auth = detector.get_service_instance(
            detector.authentication_name, authenticator=True
        )
        auth.db = detector.get_service_instance(detector.authentication_service)

        return auth

    def get_service_instance(self, service_name, global_instance=True, **kwargs):
        return detector.get_service_instance(
            service_name,
            global_instance=global_instance,
            **kwargs
        )

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
            except Exception as e:
                log.verbose("Error retrieving input parameters, {}", e)

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

    @staticmethod
    def obj_serialize(obj: StructuredNode, keys: List[str]) -> Dict[str, str]:
        attributes: Dict[str, str] = {}
        for k in keys:
            attributes[k] = EndpointResource.serialize(obj, k)

        return attributes

    @staticmethod
    def serialize(obj: StructuredNode, key: str) -> str:

        attribute = getattr(obj, key)
        if attribute is None:
            return None

        # Datetimes
        if isinstance(attribute, datetime):
            return string_from_timestamp(attribute.strftime('%s'))

        # Based on neomodel choices:
        # http://neomodel.readthedocs.io/en/latest/properties.html#choices
        choice_function = "get_{}_display".format(key)

        # Normal attribute
        if not hasattr(obj, choice_function):
            return attribute

        # Choice attribute
        fn = getattr(obj, choice_function)
        description = fn()

        return {"key": attribute, "description": description}

    def force_response(self, content=None, errors=None,
                       code=None, headers=None, head_method=False, meta=None):

        # Deprecated since 0.7.3
        log.warning("Deprecated use of self.forse_respose, replace with self.response")
        return self.response(
            content=content,
            errors=errors,
            code=code,
            headers=code,
            head_method=head_method,
            meta=meta
        )

    def response(self, content=None, errors=None,
                 code=None, headers=None, head_method=False,
                 meta=None, wrap_response=False):

        # Deprecated since 0.7.2
        if meta is not None:
            log.warning("Deprecated use of meta in response")

        if headers is None:
            headers = {}

        if wrap_response or WRAP_RESPONSE:
            response_wrapper = ResponseMaker.wrapped_response
        else:
            response_wrapper = None

        if code is None:
            code = 200

        if errors is None and content is None:
            if not head_method or code is None:
                log.warning("RESPONSE: Warning, no data and no errors")
                code = 204
        elif errors is None:
            if code >= 300:
                log.warning("Forcing 200 OK because no errors are raised")
                code = 200
        elif content is None:
            if code < 400:
                log.warning("Forcing 500 SERVER ERROR because only errors are returned")
                code = 500

        # Request from a ApiSpec endpoint, skipping all flask-related following steps
        if isinstance(self, MethodResource):
            if content is None:
                content = errors
            return (content, code, headers)

        # Convert the response in a Flask response, i.e. make_response(tuple)
        r = ResponseMaker.generate_response(
            content=content,
            code=code,
            errors=errors,
            headers=headers,
            head_method=head_method,
            meta=meta,
            response_wrapper=response_wrapper
        )

        response = make_response(r)

        # Avoid duplicated Content-type
        content_type = None
        for idx, val in enumerate(response.headers):
            if val[0] != 'Content-Type':
                continue
            if content_type is None:
                content_type = idx
                continue
            log.warning(
                "Duplicated Content-Type, removing {} and keeping {}",
                response.headers[content_type][1],
                val[1],
            )
            response.headers.pop(content_type)
            break

        return response

    def empty_response(self):
        """ Empty response as defined by the protocol """
        return self.response("", code=204)

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

        # to be deprecated
        # log.warning("Deprecated use of getJsonResponse")
        log.info("Use of getJsonResponse is discouraged and it will be deprecated soon")

        # Get id
        verify_attribute = hasattr
        if isinstance(instance, dict):
            verify_attribute = dict.get
        if verify_attribute(instance, "uuid"):
            res_id = str(instance.uuid)
        elif verify_attribute(instance, "id"):
            res_id = str(instance.id)
        else:
            res_id = None

        data = self.get_show_fields(
            instance, 'show_fields', view_public_only, fields
        )
        if not skip_missing_ids or res_id is not None:
            data['id'] = res_id

        # Relationships
        max_depth_reached = relationship_depth >= max_relationship_depth

        relationships = []
        if not max_depth_reached:

            relationships = instance.follow_relationships(
                view_public_only=view_public_only
            )

        # Used by IMC
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
                    if k in subnode:
                        log.warning(
                            "Name collision {} on node {}, model {}, property model={}",
                            k, subnode, type(node), type(r)
                        )
                    subnode[k] = attrs[k]

                subrelationship.append(subnode)

            if len(subrelationship) > 0:
                data["_{}".format(relationship)] = subrelationship

        if 'type' not in data:
            data['type'] = type(instance).__name__.lower()

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
                status_code=404,
            )
        if method not in mem.customizer._parameter_schemas[url]:
            raise RestApiException(
                "No parameters schema defined for method {} in {}".format(method, url),
                status_code=404,
            )
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
                    'Missing field: {}'.format(k), status_code=400
                )

        return properties

    def update_properties(self, instance, schema, properties):

        for field in schema:
            if isinstance(field, str):
                key = field
            else:
                if 'custom' in field:
                    if 'islink' in field['custom']:
                        if field['custom']['islink']:
                            continue
                key = field["name"]

            if key in properties:
                instance.__dict__[key] = properties[key]

    def update_sql_properties(self, instance, schema, properties):

        from sqlalchemy.orm.attributes import set_attribute
        for field in schema:
            if isinstance(field, str):
                key = field
            else:
                if 'custom' in field:
                    if 'islink' in field['custom']:
                        if field['custom']['islink']:
                            continue
                key = field["name"]

            if key in properties:
                set_attribute(instance, key, properties[key])

    def update_mongo_properties(self, instance, schema, properties):

        for field in schema:
            if isinstance(field, str):
                key = field
            else:
                if 'custom' in field:
                    if 'islink' in field['custom']:
                        if field['custom']['islink']:
                            continue
                key = field["name"]

            if key in properties:
                setattr(instance, key, properties[key])

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
            raise RestApiException(e.message, status_code=400)
