import unittest
import random
import json
import string
import logging
import os

from restapi.server import create_app
from restapi.confs import DEFAULT_HOST, DEFAULT_PORT, API_URL, AUTH_URL
from utilities.logs import get_logger
from utilities import htmlcodes as hcodes

log = get_logger(__name__)
log.setLevel(logging.DEBUG)

TEST_TROUBLESOME = True

SERVER_URI = 'http://%s:%s' % (DEFAULT_HOST, DEFAULT_PORT)
API_URI = '%s%s' % (SERVER_URI, API_URL)
AUTH_URI = '%s%s' % (SERVER_URI, AUTH_URL)

GET = 'GET'
POST = 'POST'
PUT = 'PUT'
DELETE = 'DELETE'

get = 'get'
post = 'post'
put = 'put'
delete = 'delete'

# Status aliases used to shorten method calls
OK = hcodes.HTTP_OK_BASIC                           # 200
NO_CONTENT = hcodes.HTTP_OK_NORESPONSE              # 204
PARTIAL = hcodes.HTTP_PARTIAL_CONTENT               # 206
FOUND = hcodes.HTTP_FOUND                           # 302
BAD_REQUEST = hcodes.HTTP_BAD_REQUEST               # 400
UNAUTHORIZED = hcodes.HTTP_BAD_UNAUTHORIZED         # 401
FORBIDDEN = hcodes.HTTP_BAD_FORBIDDEN               # 403
NOTFOUND = hcodes.HTTP_BAD_NOTFOUND                 # 404
NOT_ALLOWED = hcodes.HTTP_BAD_METHOD_NOT_ALLOWED    # 405
CONFLICT = hcodes.HTTP_BAD_CONFLICT                 # 409

# This error is returned by Flask when a method is not implemented [405 status]
# NOT_ALLOWED_ERROR = {
#     'message': 'The method is not allowed for the requested URL.'
# }


class ParsedResponse(object):
    pass


class TestUtilities(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        "set up test fixtures"
        print('### Setting up flask server for tests###')
        app = create_app(testing_mode=True)
        cls.app = app.test_client()

    @classmethod
    def tearDownClass(cls):
        "tear down test fixtures"
        print('### Tearing down the flask server ###')

    def get_specs(self):
        """
            Retrieve Swagger definition by calling API/specs endpoint
        """
        r = self.app.get(API_URI + '/specs')
        self.assertEqual(r.status_code, OK)
        content = json.loads(r.data.decode('utf-8'))
        return content

    def get_definition(self, specs, endpoint):
        """
            Given a swagger specs this method extracts a swagger definition
            for a specific endpoint. The endpoint is expected to have variables
            defined following swagger rules, e.g /path/{variable}
        """
        mapping = "%s/%s" % (API_URL, endpoint)

        self.assertIn(mapping, specs["paths"])
        definition = specs["paths"][mapping]

        return definition

    def save_definition(self, endpoint, label):
        specs = self.get("specs")
        definition = self.get_definition(specs, endpoint)
        self.save(label, definition)

    def get_error_message(self, definition, method, status_code):
        """
            Given a swagger definition for an endpoint, this method extracts
            the return message for a specific method and status_code
            definition[method][responses][status_code][description]
        """

        method = method.lower()
        status_code = str(status_code)

        try:
            # self.assertIn(method, definition)
            # self.assertIn("responses", definition[method])
            # self.assertIn(status_code, definition[method]["responses"])

            status_message = definition[method]["responses"][status_code]
            # self.assertIn("description", status_message)

            return status_message["description"]
        except BaseException:
            return None

    def save(self, variable, value, read_only=False):
        """
            Save a variable in the class, to be re-used in further tests
            In read_only mode the variable cannot be rewritten
        """
        if hasattr(self.__class__, variable):
            data = getattr(self.__class__, variable)
            if "read_only" in data and data["read_only"]:
                self.assertFalse(
                    "Cannot overwrite a read_only variable [%s]" % variable
                )

        data = {'value': value, 'read_only': read_only}
        setattr(self.__class__, variable, data)

    def get(self, variable):
        """
            Retrieve a previously stored variable using the .save method
        """
        if hasattr(self.__class__, variable):
            data = getattr(self.__class__, variable)
            if "value" in data:
                return data["value"]

        raise AttributeError("Class variable %s not found" % variable)
        return None

    def get_user_uuid(self, email):

        admin_headers = self.get("admin_headers")
        endpoint = 'admin/users'
        users_def = self.get("def.users")
        users = self._test_get(users_def, endpoint, admin_headers, OK)
        for x in users:
            if x.attributes.email == email:
                user = x._id
                return user

        return None

    def create_user(self, username, **kwargs):

        users_def = self.get("def.users")
        user_def = self.get("def.user")
        admin_headers = self.get("admin_headers")
        endpoint = 'admin/users'

        # This prefix ensure a strong password

        if "password" in kwargs:
            password = kwargs.pop("password")
        else:
            password = self.randomString(prefix="Aa1+")

        user = self.get_user_uuid(username)

        if user is not None:
            self._test_delete(user_def, 'admin/users/' + user,
                              admin_headers, NO_CONTENT)

        data = {}
        data['email'] = username
        data['password'] = password
        data['name'] = username
        data['surname'] = username

        for v in kwargs:
            data[v] = kwargs[v]

        # data['group'] = group
        # if irods_user is not None:
        #     data['irods_user'] = irods_user

        # if irods_cert is not None:
        #     data['irods_cert'] = irods_cert

        user = self._test_create(users_def, endpoint, admin_headers, data, OK)

        env = os.environ
        CHANGE_FIRST_PASSWORD = env.get("AUTH_FORCE_FIRST_PASSWORD_CHANGE")

        if CHANGE_FIRST_PASSWORD:
            error = "Please change your temporary password"
            self.do_login(username, password,
                          status_code=FORBIDDEN, error=error)

            new_password = self.randomString(prefix="Aa1+")
            data = {
                "new_password": new_password,
                "password_confirm": new_password
            }

            self.do_login(username, password, status_code=OK, **data)
            # password change also changes the uuid
            user = self.get_user_uuid(username)
            password = new_password

        return user, password

    def do_login(self, USER, PWD, status_code=OK, error=None, **kwargs):
        """
            Make login and return both token and authorization header
        """

        # AUTH_MAX_LOGIN_ATTEMPTS=0
        # AUTH_REGISTER_FAILED_LOGIN=False

        # AUTH_SECOND_FACTOR_AUTHENTICATION=None

        # AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=0
        # AUTH_MAX_PASSWORD_VALIDITY=0

        data = {'username': USER, 'password': PWD}
        for v in kwargs:
            data[v] = kwargs[v]

        r = self.app.post(AUTH_URI + '/login',
                          data=json.dumps(data))

        if r.status_code != OK:
            # VERY IMPORTANT FOR DEBUGGING WHEN ADVANCED AUTH OPTIONS ARE ON
            c = json.loads(r.data.decode('utf-8'))
            log.error(c['Response']['errors'])

        self.assertEqual(r.status_code, status_code)

        content = json.loads(r.data.decode('utf-8'))
        if error is not None:
            errors = content['Response']['errors']
            if errors is not None:
                self.assertEqual(errors[0], error)

        token = ''
        if content is not None:
            data = content.get('Response', {}).get('data', {})
            if data is not None:
                token = data.get('token', '')
        return {'Authorization': 'Bearer ' + token}, token

    def destroyToken(self, token, headers):
        """
            Invalidate a given token
        """
        r = self.app.get(AUTH_URI + '/tokens', headers=headers)
        self.assertEqual(r.status_code, OK)

        content = json.loads(r.data.decode('utf-8'))
        self.assertEqual(r.status_code, OK)

        for data in content['Response']['data']:
            if data["token"] == token:
                id = data["id"]
                log.info("Destroying token %s" % id)
                uri = '%s/tokens/%s' % (AUTH_URI, id)
                r = self.app.delete(uri, headers=headers)
                self.assertEqual(r.status_code, NO_CONTENT)
                break

    def get_profile(self, headers):
        r = self.app.get(AUTH_URI + '/profile', headers=headers)
        content = json.loads(r.data.decode('utf-8'))
        return content['Response']['data']

    def randomString(self, len=16, prefix="TEST:"):
        """
            Create a random string to be used to build data for tests
        """
        if len > 500000:
            lis = list(string.ascii_lowercase)
            return ''.join(random.choice(lis) for _ in range(len))

        rand = random.SystemRandom()
        charset = string.ascii_uppercase + string.digits

        random_string = prefix
        for _ in range(len):
            random_string += rand.choice(charset)

        return random_string

    def getInputSchema(self, endpoint, headers):
        """
            Retrieve a swagger-like data schema associated with a endpoint
        """
        r = self.app.get(API_URI + '/schemas/' + endpoint, headers=headers)
        self.assertEqual(r.status_code, OK)
        content = json.loads(r.data.decode('utf-8'))
        return content['Response']['data']

    def getDynamicInputSchema(self, endpoint, headers):
        """
            Retrieve a dynamic data schema associated with a endpoint
        """

        data = {"get_schema": 1}
        r = self.app.post(
            "%s/%s" % (API_URI, endpoint),
            data=data,
            headers=headers)
        self.assertEqual(r.status_code, OK)
        content = json.loads(r.data.decode('utf-8'))
        return content['Response']['data']

    def buildData(self, schema):
        """
            Input: a Swagger-like schema
            Output: a dictionary of random data
        """
        data = {}
        for d in schema:

            key = d["name"]
            type = d["type"]
            format = d.get("format", "")
            default = d.get("default", None)
            custom = d.get("custom", {})
            autocomplete = custom.get("autocomplete", False)
            test_with = custom.get("test_with", None)

            if autocomplete and test_with is None:
                continue

            value = None
            if test_with is not None:
                value = test_with
            elif 'enum' in d:
                if default is not None:
                    value = default
                elif len(d["enum"]) > 0:
                    # get first key
                    for value in d["enum"][0]:
                        break
                else:
                    value = "NOT_FOUND"
            elif type == "int":
                value = random.randrange(0, 1000, 1)
            elif format == "date":
                value = "1969-07-20"  # 20:17:40 UTC
            elif type == "multi_section":
                continue
            else:
                value = self.randomString()

            data[key] = value

        return data

    def getPartialData(self, schema, data):
        """
            Following directives contained in the schema and
            taking as input a pre-built data dictionary, this method
            remove one of the required fields from data
        """
        partialData = data.copy()
        for d in schema:
            if not d['required']:
                continue

            # key = d["key"]
            key = d["name"]

            del partialData[key]
            return partialData
        return None

    def parseResponse(self, response, inner=False):
        """
            This method is used to verify and simplify the access to
            json-standard-responses. It returns an Object built
            by mapping json content as attributes.
            This is a recursive method, the inner flag is used to
            distinguish further calls on inner elements.
        """

        if response is None:
            return None

        # OLD RESPONSE, NOT STANDARD-JSON
        if not inner and isinstance(response, dict):
            return response

        data = []

        self.assertIsInstance(response, list)

        for element in response:
            self.assertIsInstance(element, dict)
            self.assertIn("id", element)
            self.assertIn("type", element)
            self.assertIn("attributes", element)
            # # links is optional -> don't test
            # self.assertIn("links", element)
            # # relationships is optional -> don't test
            # self.assertIn("relationships", element)

            newelement = ParsedResponse()
            setattr(newelement, "_id", element["id"])
            setattr(newelement, "_type", element["type"])
            if "links" in element:
                setattr(newelement, "_links", element["links"])

            setattr(newelement, "attributes", ParsedResponse())

            for key in element["attributes"]:
                setattr(newelement.attributes, key, element["attributes"][key])

            if "relationships" in element:
                for relationship in element["relationships"]:
                    setattr(newelement, "_" + relationship,
                            self.parseResponse(
                                element["relationships"][relationship],
                                inner=True
                            ))

            data.append(newelement)

        return data

    def checkResponse(self, response, fields, relationships):
        """
        Verify that the response contains the given fields and relationships
        """

        for f in fields:
            # How to verify the existence of a property?
            # assertTrue will hide the name of the missing property
            # I can verify my self and then use an always-false assert
            if not hasattr(response[0].attributes, f):
                self.assertIn(f, [])

        for r in relationships:
            if not hasattr(response[0], "_" + r):
                self.assertIn(r, [])

    def _test_endpoint(
            self, definition, endpoint, headers=None, status_code=None):
        """
            Make standard tests on endpoint based on Swagger definition
        """

        uri = "%s/%s/%s" % (SERVER_URI, API_URL, endpoint)

        # log.critical(mapping)
        # log.critical(endpoint)

        # # # TEST GET # # #
        r = self.app.get(uri)
        code = OK if status_code is None else status_code
        if get not in definition:
            self.assertEqual(r.status_code, NOT_ALLOWED)
        elif 'security' not in definition[get]:
            self.assertEqual(r.status_code, code)
        else:

            # testing only tokens... we should verify that:
            # 'security' contains 'Bearer': []
            self.assertEqual(r.status_code, UNAUTHORIZED)

            r = self.app.get(uri, headers=headers)
            self.assertEqual(r.status_code, code)

        # # # TEST POST # # #
        r = self.app.post(uri)
        code = BAD_REQUEST if status_code is None else status_code
        if post not in definition:
            self.assertEqual(r.status_code, NOT_ALLOWED)
        elif 'security' not in definition[post]:
            self.assertEqual(r.status_code, code)
        else:
            self.assertEqual(r.status_code, UNAUTHORIZED)

            r = self.app.post(uri, headers=headers)
            self.assertEqual(r.status_code, code)

        # # # TEST PUT # # #
        r = self.app.put(uri)
        code = BAD_REQUEST if status_code is None else status_code
        if put not in definition:
            self.assertEqual(r.status_code, NOT_ALLOWED)
        elif 'security' not in definition[put]:
            self.assertEqual(r.status_code, code)
        else:
            self.assertEqual(r.status_code, UNAUTHORIZED)

            r = self.app.put(uri, headers=headers)
            self.assertEqual(r.status_code, code)

        # # # TEST DELETE # # #
        r = self.app.delete(uri)
        code = BAD_REQUEST if status_code is None else status_code
        if delete not in definition:
            self.assertEqual(r.status_code, NOT_ALLOWED)
        elif 'security' not in definition[delete]:
            self.assertEqual(r.status_code, code)
        else:
            self.assertEqual(r.status_code, UNAUTHORIZED)

            r = self.app.delete(uri, headers=headers)
            self.assertEqual(r.status_code, code)

    # headers should be optional, if auth is not required
    def _test_method(self, definition, method, endpoint, headers,
                     status, parse_response=False,
                     data=None, check_error=True, force_error=None):
        """
            Test a method (GET/POST/PUT/DELETE) on a given endpoint
            and verifies status error and optionally the returned error
            (disabled when error=False)
            It returns content['Response']['data']
            When parse_response=True the returned response
            is parsed using self.parseResponse method
        """

        uri = "%s/%s/%s" % (SERVER_URI, API_URL, endpoint)

        if data is not None:
            data = json.dumps(data)

        if method == GET:
            r = self.app.get(uri, headers=headers)
        elif method == POST:
            r = self.app.post(uri, data=data, headers=headers)
        elif method == PUT:
            r = self.app.put(uri, data=data, headers=headers)
        elif method == DELETE:
            r = self.app.delete(uri, data=data, headers=headers)

        self.assertEqual(r.status_code, status)

        if status == NO_CONTENT:
            return None

        content = json.loads(r.data.decode('utf-8'))

        # In this case the response is returned by Flask
        # if status == NOT_ALLOWED:
        #     self.assertEqual(content, NOT_ALLOWED_ERROR)
        #     return content

        if force_error is not None:
            error = force_error
        elif check_error:
            error = self.get_error_message(definition, method, status)
            if error is None:
                log.critical(
                    "Unable to find a valid message for " +
                    "status = %s, method = %s, endpoint = %s"
                    % (status, method, endpoint)
                )

            # if error is None, it will give errors in the next error assert
        else:
            error = None

        if check_error:
            errors = content['Response']['errors']
            if errors is not None:
                self.assertEqual(errors[0], error)

        if parse_response:
            return self.parseResponse(content['Response']['data'])
        return content['Response']['data']

    def _test_get(self, definition, endpoint, headers,
                  status, parse_response=True,
                  check_error=True, force_error=None):

        return self._test_method(
            definition, GET, endpoint, headers, status,
            parse_response=parse_response,
            check_error=check_error, force_error=force_error
        )

    def _test_create(self, definition, endpoint, headers, data,
                     status,
                     check_error=True, force_error=None):

        return self._test_method(
            definition, POST, endpoint, headers, status,
            data=data, check_error=check_error, force_error=force_error
        )

    # headers should be optional, if auth is not required
    def _test_update(self, definition, endpoint, headers, data,
                     status,
                     check_error=True, force_error=None):

        return self._test_method(
            definition, PUT, endpoint, headers, status,
            data=data, check_error=check_error, force_error=force_error
        )

    # headers should be optional, if auth is not required
    def _test_delete(self, definition, endpoint, headers,
                     status, data={},
                     check_error=True, force_error=None):

        return self._test_method(
            definition, DELETE, endpoint, headers, status,
            data=data, check_error=check_error, force_error=force_error
        )

    def _test_troublesome_create(self,
                                 definition, endpoint,
                                 headers, schema,
                                 second_definition, second_endpoint=None,
                                 status_configuration={}):

        if not TEST_TROUBLESOME:
            log.critical("---- SKIPPING TROUBLESOME TESTS ----")
            return
        """
            Test several troublesome conditions based on field types
                (obtained from json schema)
            If POST call returns a 200 OK PUT and DELETE are also called
            (by using second_definition and second_endpoint parameters)

            returned status code can be overwritten by providing a
                status_configuration dictionary, e.g:
                    status_conf = {}
                    status_conf["NEGATIVE_NUMBER"] = BAD_REQUEST
                    status_conf["LONG_NUMBER"] = BAD_REQUEST
        """

        troublesome_tests = {}
        troublesome_tests["EXTERNAL_DOUBLE_QUOTES"] = ["text", OK]
        troublesome_tests["EXTERNAL_SINGLE_QUOTES"] = ["text", OK]
        troublesome_tests["INTERNAL_DOUBLE_QUOTES"] = ["text", OK]
        troublesome_tests["INTERNAL_SINGLE_QUOTES"] = ["text", OK]
        troublesome_tests["INTERNAL_SINGLE_QUOTES"] = ["text", OK]
        troublesome_tests["LONG_TEXT"] = ["text", OK]
        troublesome_tests["VERY_LONG_TEXT"] = ["text", OK]
        # troublesome_tests["EXTREMELY_LONG_TEXT"] = ["text", OK]
        # troublesome_tests["TOOOO_LONG_TEXT"] = ["text", OK]
        troublesome_tests["LETTERS_WITH_ACCENTS"] = ["text", OK]
        # troublesome_tests["SPECIAL_CHARACTERS"] = ["text", OK]
        troublesome_tests["EMPTY_STRING"] = ["text", BAD_REQUEST]
        troublesome_tests["NEGATIVE_NUMBER"] = ["int", OK]
        troublesome_tests["ZERO"] = ["int", OK]
        troublesome_tests["LONG_NUMBER"] = ["int", OK]
        troublesome_tests["TOO_LONG_NUMBER"] = ["int", OK]
        troublesome_tests["NOT_A_NUMBER"] = ["int", BAD_REQUEST]
        troublesome_tests["UNEXPECTED_OPTION"] = ["select", BAD_REQUEST]
        data = self.buildData(schema)

        for trouble_type in troublesome_tests:

            t_type = troublesome_tests[trouble_type][0]
            if trouble_type in status_configuration:
                t_status = status_configuration[trouble_type]
                post_status = t_status
                put_status = t_status
            else:
                t_status = troublesome_tests[trouble_type][1]
                post_status = t_status
                put_status = t_status
                if put_status == OK:
                    put_status = NO_CONTENT

            post_data = data.copy()
            put_data = data.copy()
            t_found = False

            for s in schema:

                s_type = s["type"]

                # We are unable to automatically test autocomplete fields
                custom = s.get("custom", {})
                autocomplete = custom.get("autocomplete", False)
                if autocomplete:
                    continue

                if "format" in s:
                    if s['format'] == 'date':
                        s_type = 'date'

                if s_type == "string":
                    s_type = "text"

                if 'enum' in s:
                    s_type = "select"

                if s_type != t_type:
                    continue

                field_key = s["name"]
                trouble = self.applyTroubles(data[field_key], trouble_type)
                post_data[field_key] = trouble
                put_data[field_key] = trouble
                t_found = True

            if not t_found:
                print(
                    "\t *** SKIPPING TEST %s - type %s not found" %
                    (trouble_type, t_type))
                continue

            print("\t *** TESTING %s " % trouble_type)

            id = self._test_create(
                definition, endpoint, headers, post_data, post_status,
                check_error=False)

            if post_status != OK:
                continue

            if id is None:
                continue

            if second_endpoint is None:
                tmp_ep = "%s/%s" % (endpoint, id)
            else:
                tmp_ep = "%s/%s" % (second_endpoint, id)

            self._test_update(
                second_definition, tmp_ep, headers,
                put_data, put_status,
                check_error=False)

            self._test_delete(
                second_definition, tmp_ep, headers, NO_CONTENT)

    def applyTroubles(self, data, trouble_type):
        """
            Applies one of known troublesome conditions to a prefilled data.
            Returned value can contain or not the original data, depending
                on the specific trouble type
        """

        if trouble_type == 'EMPTY_STRING':
            return ""
        if trouble_type == 'NEGATIVE_NUMBER':
            return -42
        if trouble_type == 'ZERO':
            return 0
        if trouble_type == 'LONG_NUMBER':
            return 2147483648
        if trouble_type == 'TOO_LONG_NUMBER':
            return 18446744073709551616
        if trouble_type == 'NOT_A_NUMBER':
            return "THIS_IS_NOT_A_NUMBER"

        if isinstance(data, str):
            strlen = len(data)
            halflen = int(strlen / 2)
            prefix = data[:halflen]
            suffix = data[halflen:]

            if trouble_type == 'EXTERNAL_DOUBLE_QUOTES':
                return '%s%s%s' % ("\"", data, "\"")
            if trouble_type == 'EXTERNAL_SINGLE_QUOTES':
                return '%s%s%s' % ("\'", data, "\'")
            if trouble_type == 'INTERNAL_DOUBLE_QUOTES':
                return '%s%s%s' % ("PRE_\"", data, "\"_POST")
            if trouble_type == 'INTERNAL_SINGLE_QUOTES':
                return '%s%s%s' % ("PRE_\'", data, "\'_POST")
            if trouble_type == 'LETTERS_WITH_ACCENTS':
                return '%s%s%s' % (prefix, "àèìòùé", suffix)
            if trouble_type == 'SPECIAL_CHARACTERS':
                return '%s%s%s' % (prefix, "૱꠸┯┰┱┲❗►◄ĂăǕǖꞀ¤Ð¢℥Ω℧Kℶℷℸⅇ⅊⚌⚍⚎⚏⚭⚮⌀⏑⏒⏓⏔⏕⏖⏗⏘⏙⏠⏡⏦ᶀᶁᶂᶃᶄᶆᶇᶈᶉᶊᶋᶌᶍᶎᶏᶐᶑᶒᶓᶔᶕᶖᶗᶘᶙᶚᶸᵯᵰᵴᵶᵹᵼᵽᵾᵿ  ‌‍‎‏ ⁁⁊ ⁪⁫⁬⁭⁮⁯⸜⸝¶¥£⅕⅙⅛⅔⅖⅗⅘⅜⅚⅐⅝↉⅓⅑⅒⅞←↑→↓↔↕↖↗↘↙↚↛↜↝↞↟↠↡↢↣↤↥↦↧↨↩↪↫↬↭↮↯↰↱↲↳↴↵↶↷↸↹↺↻↼↽↾↿⇀⇁⇂⇃⇄⇅⇆⇇⇈⇉⇊⇋⇌⇍⇎⇏⇐⇑⇒⇓⇔⇕⇖⇗⇘⇙⇚⇛⇜⇝⇞⇟⇠⇡⇢⇣⇤⇥⇦⇨⇩⇪⇧⇫⇬⇭⇮⇯⇰⇱⇲⇳⇴⇵⇶⇷⇸⇹⇺⇻⇼⇽⇾⇿⟰⟱⟲⟳⟴⟵⟶⟷⟸⟹⟺⟻⟼⟽⟾⟿⤀⤁⤂⤃⤄⤅⤆⤇⤈⤉⤊⤋⤌⤍⤎⤏⤐⤑⤒⤓⤔⤕⤖⤗⤘⤙⤚⤛⤜⤝⤞⤟⤠⤡⤢⤣⤤⤥⤦⤧⤨⤩⤪⤫⤬⤭⤮⤯⤰⤱⤲⤳⤴⤵⤶⤷⤸⤹⤺⤻⤼⤽⤾⤿⥀⥁⥂⥃⥄⥅⥆⥇⥈⥉⥊⥋⥌⥍⥎⥏⥐⥑⥒⥓⥔⥕⥖⥗⥘⥙⥚⥛⥜⥝⥞⥟⥠⥡⥢⥣⥤⥥⥦⥧⥨⥩⥪⥫⥬⥭⥮⥯⥰⥱⥲⥳⥴⥵⥶⥷⥸⥹⥺⥻⥼⥽⥾⥿➔➘➙➚➛➜➝➞➝➞➟➠➡➢➣➤➥➦➧➨➩➩➪➫➬➭➮➯➱➲➳➴➵➶➷➸➹➺➻➼➽➾⬀⬁⬂⬃⬄⬅⬆⬇⬈⬉⬊⬋⬌⬍⬎⬏⬐⬑☇☈⏎⍃⍄⍅⍆⍇⍈⍐⍗⍌⍓⍍⍔⍏⍖♾⎌☊☋☌☍⌃⌄⌤⌅⌆⌇⚋⚊⌌⌍⌎⌏⌐⌑⌔⌕⌗⌙⌢⌣⌯⌬⌭⌮⌖⌰⌱⌲⌳⌴⌵⌶⌷⌸⌹⌺⌻⌼⍯⍰⌽⌾⌿⍀⍁⍂⍉⍊⍋⍎⍏⍑⍒⍕⍖⍘⍙⍚⍛⍜⍝⍞⍠⍟⍡⍢⍣⍤⍥⍨⍩⍦⍧⍬⍿⍪⍮⍫⍱⍲⍭⍳⍴⍵⍶⍷⍸⍹⍺⍼⍽⍾⎀⎁⎂⎃⎄⎅⎆⎉⎊⎋⎍⎎⎏⎐⎑⎒⎓⎔⎕⏣⌓⏥⏢⎖⎲⎳⎴⎵⎶⎸⎹⎺⎻⎼⎽⎾⎿⏀⏁⏂⏃⏄⏅⏆⏇⏈⏉⏉⏋⏌⏍⏐⏤⏚⏛Ⓝℰⓦ!   ⌘«»‹›‘’“”„‚❝❞£¥€$¢¬¶@§®©™°×π±√‰Ω∞≈÷~≠¹²³½¼¾‐–—|⁄\[]{}†‡…·•●⌥⌃⇧↩¡¿‽⁂∴∵◊※←→↑↓☜☞☝☟✔★☆♺☼☂☺☹☃✉✿✄✈✌✎♠♦♣♥♪♫♯♀♂αßÁáÀàÅåÄäÆæÇçÉéÈèÊêÍíÌìÎîÑñÓóÒòÔôÖöØøÚúÙùÜüŽž₳฿￠€₡¢₢₵₫￡£₤₣ƒ₲₭₥₦₱＄$₮₩￦¥￥₴₰¤៛₪₯₠₧₨௹﷼㍐৲৳~ƻƼƽ¹¸¬¨ɂǁ¯Ɂǂ¡´°ꟾ¦}{|.,·])[/_\¿º§\"*-+(!&%$¼¾½¶©®@ẟⱿ`Ȿ^꜠꜡ỻ'=:;<ꞌꞋ꞊ꞁꞈ꞉>?÷ℾℿ℔℩℉⅀℈þðÞµªꝋꜿꜾⱽⱺⱹⱷⱶⱵⱴⱱⱰⱦȶȴȣȢȡȝȜțȋȊȉȈǯǮǃǀƿƾƺƹƸƷƲưƪƣƢƟƛƖƕƍſỽ⸀⸁⸂⸃⸄⸅⸆⸇⸈⸉⸊⸋⸌⸍⸎⸏⸐⸑⸒⸔⸕▲▼◀▶◢◣◥◤△▽◿◺◹◸▴▾◂▸▵▿◃▹◁▷◅▻◬⟁⧋⧊⊿∆∇◭◮⧩⧨⌔⟐◇◆◈⬖⬗⬘⬙⬠⬡⎔⋄◊⧫⬢⬣▰▪◼▮◾▗▖■∎▃▄▅▆▇█▌▐▍▎▉▊▋❘❙❚▀▘▝▙▚▛▜▟▞░▒▓▂▁▬▔▫▯▭▱◽□◻▢⊞⊡⊟⊠▣▤▥▦⬚▧▨▩⬓◧⬒◨◩◪⬔⬕❏❐❑❒⧈◰◱◳◲◫⧇⧅⧄⍁⍂⟡⧉○◌◍◎◯❍◉⦾⊙⦿⊜⊖⊘⊚⊛⊝●⚫⦁◐◑◒◓◔◕⦶⦸◵◴◶◷⊕⊗⦇⦈⦉⦊❨❩⸨⸩◖◗❪❫❮❯❬❭❰❱⊏⊐⊑⊒◘◙◚◛◜◝◞◟◠◡⋒⋓⋐⋑╰╮╭╯⌒╳✕╱╲⧸⧹⌓◦❖✖✚✜⧓⧗⧑⧒⧖_⚊╴╼╾‐⁃‑‒-–⎯—―╶╺╸─━┄┅┈┉╌╍═≣≡☰☱☲☳☴☵☶☷╵╷╹╻│▕▏┃┆┇┊╎┋╿╽┌┍┎┏┐┑┒┓└┕┖┗┘┙┚┛├┝┞┟┠┡┢┣┤┥┦┧┨┩┪┫┬┭┮┳┴┵┶┷┸┹┺┻┼┽┾┿╀╁╂╃╄╅╆╇╈╉╊╋╏║╔╒╓╕╖╗╚╘╙╛╜╝╞╟╠╡╢╣╤╥╦╧╨╩╪╫╬⌞⌟⌜⌝⌊⌋⌉⌈⌋₯ἀἁἂἃἄἅἆἇἈἉἊἋἌἍἎἏἐἑἒἓἔἕἘἙἚἛἜἝἠἡἢἣἤἥἦἧἨἩἪἫἬἭἮἯἰἱἲἳἴἵἶἷἸἹἺἻἼἽἾἿὀὁὂὃὄὅὈὉὊὋὌὍὐὑὒὓὔὕὖὗὙὛὝὟὠὡὢὣὤὥὦὧὨὩὪὫὬὭὮὯὰάὲέὴήὶίὸόὺύὼώᾀᾁᾂᾃᾄᾅᾆᾇᾈᾉᾊᾋᾌᾍᾎᾏᾐᾑᾒᾓᾔᾕᾖᾗᾘᾙᾚᾛᾜᾝᾞᾟᾠᾡᾢᾣᾤᾥᾦᾧᾨᾩᾪᾫᾬᾭᾮᾯᾰᾱᾲᾳᾴᾶᾷᾸᾹᾺΆᾼ᾽ι᾿῀῁ῂῃῄῆῇῈΈῊΉῌ῍῎῏ῐῑῒΐῖῗῘῙῚΊ῝῞῟ῠῡῢΰῤῥῦῧῨῩῪΎῬ῭΅`ῲῳῴῶῷῸΌῺΏῼ´῾ͰͱͲͳʹ͵Ͷͷͺͻͼͽ;΄΅Ά·ΈΉΊΌΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώϐϑϒϓϔϕϖϗϘϙϚϛϜϝϞϟϠϡϢϣϤϥϦϧϨϩϪϫϬϭϮϯϰϱϲϳϴϵ϶ϷϸϹϺϻϼϽϾϿⒶⓐ⒜AaẠạẢảḀḁÂÃǍǎẤấẦầẨẩȂȃẪẫẬậÀÁẮắẰằẲẳẴẵẶặĀāĄąǞȀȁÅǺǻÄäǟǠǡâáåãàẚȦȧȺÅⱥÆæǼǢǣⱯꜲꜳꜸꜺⱭꜹꜻª℀⅍℁Ⓑⓑ⒝BbḂḃḄḅḆḇƁɃƀƃƂƄƅℬⒸⓒ⒞CcḈḉĆćĈĉĊċČčÇçƇƈȻȼℂ℃ℭƆ℅℆℄ꜾꜿⒹⓓ⒟DdḊḋḌḍḎḏḐḑḒḓĎďƊƋƌƉĐđȡⅅⅆǱǲǳǄǅǆȸⒺⓔ⒠EeḔḕḖḗḘḙḚḛḜḝẸẹẺẻẾếẼẽỀềỂểỄễỆệĒēĔĕĖėĘęĚěÈèÉéÊêËëȄȅȨȩȆȇƎⱸɆℇℯ℮ƐℰƏǝⱻɇⒻⓕ⒡FfḞḟƑƒꜰℲⅎꟻℱ℻Ⓖⓖ⒢GgƓḠḡĜĝĞğĠġĢģǤǥǦǧǴℊ⅁ǵⒽⓗ⒣HhḢḣḤḥḦḧḨḩḪḫẖĤĥȞȟĦħⱧⱨꜦℍǶℏℎℋℌꜧⒾⓘ⒤IiḬḭḮḯĲĳìíîïÌÍÎÏĨĩĪīĬĭĮįıƗƚỺǏǐⅈⅉℹℑℐⒿⓙ⒥JjĴĵȷⱼɈɉǰⓀⓚ⒦KkḰḱḲḳḴḵĶķƘƙꝀꝁꝂꝃꝄꝅǨǩⱩⱪĸⓁⓛ⒧LlḶḷḸḹḺḻḼḽĹĺĻļĽİľĿŀŁłỈỉỊịȽⱠꝈꝉⱡⱢꞁℒǇǈǉ⅃⅂ℓȉȈȊȋⓂⓜ⒨MmḾḿṀṁṂṃꟿꟽⱮƩƜℳⓃⓝ⒩NnṄṅṆṇṈṉṊṋŃńŅņŇňǸǹŊƝñŉÑȠƞŋǊǋǌȵℕ№OoṌṍṎṏṐṑṒṓȪȫȬȭȮȯȰȱǪǫǬǭỌọỎỏỐốỒồỔổỖỗỘộỚớỜờỞởỠỡỢợƠơŌōŎŏŐőÒÓÔÕÖǑȌȍȎȏŒœØǾꝊǽǿℴ⍥⍤Ⓞⓞ⒪òóôõöǒøꝎꝏⓅⓟ⒫℗PpṔṕṖṗƤƥⱣℙǷꟼ℘Ⓠⓠ⒬QqɊɋℚ℺ȹⓇⓡ⒭RrŔŕŖŗŘřṘṙṚṛṜṝṞṟȐȑȒȓɍɌƦⱤ℞Ꝛꝛℜℛ℟ℝⓈⓢ⒮SsṠṡṢṣṤṥṦṧṨṩŚśŜŝŞşŠšȘșȿꜱƧƨẞßẛẜẝ℠Ⓣⓣ⒯TtṪṫṬṭṮṯṰṱŢţŤťŦŧƬƮẗȚȾƫƭțⱦȶ℡™Ⓤⓤ⒰UuṲṳṴṵṶṷṸṹṺṻỤỦủỨỪụứỬửừữỮỰựŨũŪūŬŭŮůŰűǙǚǗǘǛǜŲųǓǔȔȕÛûȖȗÙùÜüƯúɄưƲƱⓋⓥ⒱VvṼṽṾṿỼɅ℣ⱱⱴⱽⓌⓦ⒲WwẀẁẂẃẄẅẆẇẈẉŴŵẘⱲⱳⓍⓧ⒳XxẊẋẌẍℵ×Ⓨⓨ⒴yYẎẏỾỿẙỲỳỴỵỶỷỸỹŶŷƳƴŸÿÝýɎɏȲƔ⅄ȳℽⓏⓩ⒵ZzẐẑẒẓẔẕŹźŻżŽžȤȥⱫⱬƵƶɀℨℤ⟀⟁⟂⟃⟄⟇⟈⟉⟊⟐⟑⟒⟓⟔⟕⟖⟗⟘⟙⟚⟛⟜⟝⟞⟟⟠⟡⟢⟣⟤⟥⟦⟧⟨⟩⟪⟫⦀⦁⦂⦃⦄⦅⦆⦇⦈⦉⦊⦋⦌⦍⦎⦏⦐⦑⦒⦓⦔⦕⦖⦗⦘⦙⦚⦛⦜⦝⦞⦟⦠⦡⦢⦣⦤⦥⦦⦧⦨⦩⦪⦫⦬⦭⦮⦯⦰⦱⦲⦳⦴⦵⦶⦷⦸⦹⦺⦻⦼⦽⦾⦿⧀⧁⧂⧃⧄⧅⧆⧇⧈⧉⧊⧋⧌⧍⧎⧏⧐⧑⧒⧓⧔⧕⧖⧗⧘⧙⧚⧛⧜⧝⧞⧟⧡⧢⧣⧤⧥⧦⧧⧨⧩⧪⧫⧬⧭⧮⧯⧰⧱⧲⧳⧴⧵⧶⧷⧸⧹⧺⧻⧼⧽⧾⧿∀∁∂∃∄∅∆∇∈∉∊∋∌∍∎∏∐∑−∓∔∕∖∗∘∙√∛∜∝∞∟∠∡∢∣∤∥∦∧∨∩∪∫∬∭∮∯∰∱∲∳∴∵∶∷∸∹∺∻∼∽∾∿≀≁≂≃≄≅≆≇≈≉≊≋≌≍≎≏≐≑≒≓≔≕≖≗≘≙≚≛≜≝≞≟≠≡≢≣≤≥≦≧≨≩≪≫≬≭≮≯≰≱≲≳≴≵≶≷≸≹≺≻≼≽≾≿⊀⊁⊂⊃⊄⊅⊆⊇⊈⊉⊊⊋⊌⊍⊎⊏⊐⊑⊒⊓⊔⊕⊖⊗⊘⊙⊚⊛⊜⊝⊞⊟⊠⊡⊢⊣⊤⊥⊦⊧⊨⊩⊪⊫⊬⊭⊮⊯⊰⊱⊲⊳⊴⊵⊶⊷⊸⊹⊺⊻⊼⊽⊾⊿⋀⋁⋂⋃⋄⋅⋆⋇⋈⋉⋊⋋⋌⋍⋎⋏⋐⋑⋒⋓⋔⋕⋖⋗⋘⋙⋚⋛⋜⋝⋞⋟⋠⋡⋢⋣⋤⋥⋦⋧⋨⋩⋪⋫⋬⋭⋮⋯⋰⋱⋲⋳⋴⋵⋶⋷⋸⋹⋺⋻⋼⋽⋾⋿✕✖✚◀▶❝❞★☆☼☂☺☹✄✈✌✎♪♫☀☁☔⚡❆☽☾✆✔☯☮☠⚑☬✄✏♰✡✰✺⚢⚣♕♛♚♬ⓐⓑⓒⓓ↺↻⇖⇗⇘⇙⟵⟷⟶⤴⤵⤶⤷➫➬€₤＄₩₪⟁⟐◆⎔░▢⊡▩⟡◎◵⊗❖ΩβΦΣΞ⟁⦻⧉⧭⧴∞≌⊕⋍⋰⋱✖⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾ᴕ⸨⸩❪❫⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾⒈⒉⒊⒋⒌⒍⒎⒏⒐⒑⒒⒓⒔⒕⒖⒗⒘⒙⒚⒛⓪①②③④⑤⑥⑦⑧⑨⑩➀➁➂➃➄➅➆➇➈➉⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳⓿❶❷❸❹❺❻❼❽❾❿➊➋➌➍➎➏➐➑➒➓⓫⓬⓭⓮⓯⓰⓱⓲⓳⓴⑴⑵⑶⑷⑸⑹⑺⑻⑼⑽⑾⑿⒀⒁⒂⒃⒄⒅⒆⒇ᶅᶛᶜᶝᶞᶟᶠᶡᶢᶣᶤᶥᶦᶧᶨᶩᶪᶫᶬᶭᶮᶯᶰᶱᶲᶳᶴᶵᶶᶷᶹᶺᶻᶼᶽᶾᶿᴀᴁᴂᴃᴄᴅᴆᴇᴈᴉᴊᴋᴌᴍᴎᴏᴐᴑᴒᴓᴔᴕᴖᴗᴘᴙᴚᴛᴜᴝᴞᴟᴠᴡᴢᴣᴤᴥᴦᴧᴨᴩᴪᴫᴬᴭᴮᴯᴰᴱᴲᴳᴴᴵᴶᴷᴸᴹᴺᴻᴼᴽᴾᴿᵀᵁᵂᵃᵄᵅᵆᵇᵈᵉᵊᵋᵌᵍᵎᵏᵐᵑᵒᵓᵔᵕᵖᵗᵘᵙᵚᵛᵜᵝᵞᵟᵠᵡᵢᵣᵤᵥᵦᵧᵨᵩᵪᵫᵬᵭᵮᵱᵲᵳᵵᵷᵸᵺᵻ᷎᷏᷋᷌ᷓᷔᷕᷖᷗᷘᷙᷛᷜᷝᷞᷟᷠᷡᷢᷣᷤᷥᷦ᷍‘’‛‚“”„‟«»‹›Ꞌ❛❜❝❞<>@‧¨․꞉:⁚⁝⁞‥…⁖⸪⸬⸫⸭⁛⁘⁙⁏;⦂⁃‐‑‒-–⎯—―_⁓⸛⸞⸟ⸯ¬/\⁄\⁄|⎜¦‖‗†‡·•⸰°‣⁒%‰‱&⅋§÷+±=꞊′″‴⁗‵‶‷‸*⁑⁎⁕※⁜⁂!‼¡?¿⸮⁇⁉⁈‽⸘¼½¾²³©®™℠℻℅℁⅍℄¶⁋❡⁌⁍⸖⸗⸚⸓()[]{}⸨⸩❨❩❪❫⸦⸧❬❭❮❯❰❱❴❵❲❳⦗⦘⁅⁆〈〉⏜⏝⏞⏟⸡⸠⸢⸣⸤⸥⎡⎤⎣⎦⎨⎬⌠⌡⎛⎠⎝⎞⁀⁔‿⁐‾⎟⎢⎥⎪ꞁ⎮⎧⎫⎩⎭⎰⎱✈☀☼☁☂☔⚡❄❅❆☃☉☄★☆☽☾⌛⌚☇☈⌂⌁✆☎☏☑✓✔⎷⍻✖✗✘☒✕☓☕♿✌☚☛☜☝☞☟☹☺☻☯⚘☮✝⚰⚱⚠☠☢⚔⚓⎈⚒⚑⚐☡❂⚕⚖⚗✇☣⚙☤⚚⚛⚜☥☦☧☨☩†☪☫☬☭✁✂✃✄✍✎✏✐✑✒✉✙✚✜✛♰♱✞✟✠✡☸✢✣✤✥✦✧✩✪✫✬✭✮✯✰✲✱✳✴✵✶✷✸✹✺✻✼✽✾❀✿❁❃❇❈❉❊❋⁕☘❦❧☙❢❣♀♂⚢⚣⚤⚦⚧⚨⚩☿♁⚯♔♕♖♗♘♙♚♛♜♝♞♟☖☗♠♣♦♥❤❥♡♢♤♧⚀⚁⚂⚃⚄⚅⚇⚆⚈⚉♨♩♪♫♬♭♮♯⌨⏏⎗⎘⎙⎚⌥⎇⌘⌦⌫⌧♲♳♴♵♶♷♸♹♺♻♼♽⁌⁍⎌⌇⌲⍝⍟⍣⍤⍥⍨⍩⎋♃♄♅♆♇♈♉♊♋♌♍♎♏♐♑♒♓⏚⏛​|",suffix)
            if trouble_type == 'LONG_TEXT':
                return '%s%s%s' % (prefix, self.randomString(len=256, prefix=""), suffix)
            if trouble_type == 'VERY_LONG_TEXT':
                return '%s%s%s' % (prefix, self.randomString(len=65536, prefix=""), suffix)
            if trouble_type == 'EXTREMELY_LONG_TEXT':
                return '%s%s%s' % (prefix, self.randomString(len=16777216, prefix=""), suffix)
            if trouble_type == 'TOOOO_LONG_TEXT':
                return '%s%s%s' % (prefix, self.randomString(len=4294967296, prefix=""), suffix)

        if trouble_type == 'UNEXPECTED_OPTION':
            return self.randomString()

        self.assertFalse("Unexpected trouble: %s" % trouble_type)
        return data
