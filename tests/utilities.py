"""

    THIS SCRIPT IS OBSOLETE!
    I'm moving what is need for py.test in restapi/tests/__init__.py
"""
import unittest
import json

import logging
import os

from restapi.confs import DEFAULT_HOST, DEFAULT_PORT, API_URL, AUTH_URL
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.logs import get_logger

log = get_logger(__name__)
log.setLevel(logging.DEBUG)

TEST_TROUBLESOME = True

SERVER_URI = 'http://{}:{}'.format(DEFAULT_HOST, DEFAULT_PORT)
API_URI = '{}{}'.format(SERVER_URI, API_URL)
AUTH_URI = '{}{}'.format(SERVER_URI, AUTH_URL)

GET = 'GET'
POST = 'POST'
PUT = 'PUT'
DELETE = 'DELETE'

get = 'get'
post = 'post'
put = 'put'
delete = 'delete'

# Status aliases used to shorten method calls
OK = hcodes.HTTP_OK_BASIC  # 200
NO_CONTENT = hcodes.HTTP_OK_NORESPONSE  # 204
PARTIAL = hcodes.HTTP_PARTIAL_CONTENT  # 206
FOUND = hcodes.HTTP_FOUND  # 302
BAD_REQUEST = hcodes.HTTP_BAD_REQUEST  # 400
UNAUTHORIZED = hcodes.HTTP_BAD_UNAUTHORIZED  # 401
FORBIDDEN = hcodes.HTTP_BAD_FORBIDDEN  # 403
NOTFOUND = hcodes.HTTP_BAD_NOTFOUND  # 404
NOT_ALLOWED = hcodes.HTTP_BAD_METHOD_NOT_ALLOWED  # 405
CONFLICT = hcodes.HTTP_BAD_CONFLICT  # 409

# This error is returned by Flask when a method is not implemented [405 status]
# NOT_ALLOWED_ERROR = {
#     'message': 'The method is not allowed for the requested URL.'
# }


class ParsedResponse(object):
    pass


class TestUtilities(unittest.TestCase):
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
            self._test_delete(
                user_def, 'admin/users/' + user, admin_headers, NO_CONTENT
            )

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
            self.do_login(username, password, status_code=FORBIDDEN, error=error)

            new_password = self.randomString(prefix="Aa1+")
            data = {"new_password": new_password, "password_confirm": new_password}

            self.do_login(username, password, status_code=OK, **data)
            # password change also changes the uuid
            user = self.get_user_uuid(username)
            password = new_password

        return user, password

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
                log.info("Destroying token {}", data["id"])
                uri = '{}/tokens/{}'.format(AUTH_URI, data["id"])
                r = self.app.delete(uri, headers=headers)
                self.assertEqual(r.status_code, NO_CONTENT)
                break

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

        assert isinstance(response, list)

        for element in response:
            assert isinstance(element, dict)
            assert "id" in element
            assert "type" in element
            assert "attributes" in element
            # # links is optional -> don't test
            assert "links" in element
            # # relationships is optional -> don't test
            assert "relationships" in element

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
                    setattr(
                        newelement,
                        "_" + relationship,
                        self.parseResponse(
                            element["relationships"][relationship], inner=True
                        ),
                    )

            data.append(newelement)

        return data

    def _test_endpoint(self, definition, endpoint, headers=None, status_code=None):
        """
            Make standard tests on endpoint based on Swagger definition
        """

        uri = "{}/{}/{}".format(SERVER_URI, API_URL, endpoint)

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
    def _test_method(
        self,
        definition,
        method,
        endpoint,
        headers,
        status,
        parse_response=False,
        data=None,
        check_error=True,
        force_error=None,
    ):
        """
            Test a method (GET/POST/PUT/DELETE) on a given endpoint
            and verifies status error and optionally the returned error
            (disabled when error=False)
            It returns content['Response']['data']
            When parse_response=True the returned response
            is parsed using self.parseResponse method
        """

        uri = "{}/{}/{}".format(SERVER_URI, API_URL, endpoint)

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
                    "No message found for status = {}, method = {}, endpoint = {}",
                    status, method, endpoint
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

    def _test_get(
        self,
        definition,
        endpoint,
        headers,
        status,
        parse_response=True,
        check_error=True,
        force_error=None,
    ):

        return self._test_method(
            definition,
            GET,
            endpoint,
            headers,
            status,
            parse_response=parse_response,
            check_error=check_error,
            force_error=force_error,
        )

    def _test_create(
        self,
        definition,
        endpoint,
        headers,
        data,
        status,
        check_error=True,
        force_error=None,
    ):

        return self._test_method(
            definition,
            POST,
            endpoint,
            headers,
            status,
            data=data,
            check_error=check_error,
            force_error=force_error,
        )

    # headers should be optional, if auth is not required
    def _test_update(
        self,
        definition,
        endpoint,
        headers,
        data,
        status,
        check_error=True,
        force_error=None,
    ):

        return self._test_method(
            definition,
            PUT,
            endpoint,
            headers,
            status,
            data=data,
            check_error=check_error,
            force_error=force_error,
        )

    # headers should be optional, if auth is not required
    def _test_delete(
        self,
        definition,
        endpoint,
        headers,
        status,
        data={},
        check_error=True,
        force_error=None,
    ):

        return self._test_method(
            definition,
            DELETE,
            endpoint,
            headers,
            status,
            data=data,
            check_error=check_error,
            force_error=force_error,
        )

    def _test_troublesome_create(
        self,
        definition,
        endpoint,
        headers,
        schema,
        second_definition,
        second_endpoint=None,
        status_configuration={},
    ):

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
                    "\t *** SKIPPING TEST {} - type {} not found"
                    .format(trouble_type, t_type)
                )
                continue

            print("\t *** TESTING {}".format(trouble_type))

            id = self._test_create(
                definition, endpoint, headers, post_data, post_status, check_error=False
            )

            if post_status != OK:
                continue

            if id is None:
                continue

            if second_endpoint is None:
                tmp_ep = "{}/{}".format(endpoint, id)
            else:
                tmp_ep = "{}/{}".format(second_endpoint, id)

            self._test_update(
                second_definition,
                tmp_ep,
                headers,
                put_data,
                put_status,
                check_error=False,
            )

            self._test_delete(second_definition, tmp_ep, headers, NO_CONTENT)

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
                return '{}{}{}'.format("\"", data, "\"")
            if trouble_type == 'EXTERNAL_SINGLE_QUOTES':
                return '{}{}{}'.format("\'", data, "\'")
            if trouble_type == 'INTERNAL_DOUBLE_QUOTES':
                return '{}{}{}'.format("PRE_\"", data, "\"_POST")
            if trouble_type == 'INTERNAL_SINGLE_QUOTES':
                return '{}{}{}'.format("PRE_\'", data, "\'_POST")
            if trouble_type == 'LETTERS_WITH_ACCENTS':
                return '{}{}{}'.format(prefix, "àèìòùé", suffix)
            if trouble_type == 'SPECIAL_CHARACTERS':
                return '{}{}{}'.format(
                    prefix,
                    "૱꠸┯┰┱┲❗►◄ĂăǕǖꞀ¤Ð¢℥Ω℧Kℶℷℸⅇ⅊⚌⚍⚎⚏⚭⚮⌀⏑⏒⏓⏔⏕⏖⏗⏘⏙⏠⏡⏦ᶀᶁᶂᶃᶄᶆᶇᶈᶉᶊᶋᶌᶍᶎᶏᶐᶑᶒᶓᶔᶕᶖᶗᶘᶙᶚᶸᵯᵰᵴᵶᵹᵼᵽᵾᵿ  ‌‍‎‏ ⁁⁊ ⁪⁫⁬⁭⁮⁯⸜⸝¶¥£⅕⅙⅛⅔⅖⅗⅘⅜⅚⅐⅝↉⅓⅑⅒⅞←↑→↓↔↕↖↗↘↙↚↛↜↝↞↟↠↡↢↣↤↥↦↧↨↩↪↫↬↭↮↯↰↱↲↳↴↵↶↷↸↹↺↻↼↽↾↿⇀⇁⇂⇃⇄⇅⇆⇇⇈⇉⇊⇋⇌⇍⇎⇏⇐⇑⇒⇓⇔⇕⇖⇗⇘⇙⇚⇛⇜⇝⇞⇟⇠⇡⇢⇣⇤⇥⇦⇨⇩⇪⇧⇫⇬⇭⇮⇯⇰⇱⇲⇳⇴⇵⇶⇷⇸⇹⇺⇻⇼⇽⇾⇿⟰⟱⟲⟳⟴⟵⟶⟷⟸⟹⟺⟻⟼⟽⟾⟿⤀⤁⤂⤃⤄⤅⤆⤇⤈⤉⤊⤋⤌⤍⤎⤏⤐⤑⤒⤓⤔⤕⤖⤗⤘⤙⤚⤛⤜⤝⤞⤟⤠⤡⤢⤣⤤⤥⤦⤧⤨⤩⤪⤫⤬⤭⤮⤯⤰⤱⤲⤳⤴⤵⤶⤷⤸⤹⤺⤻⤼⤽⤾⤿⥀⥁⥂⥃⥄⥅⥆⥇⥈⥉⥊⥋⥌⥍⥎⥏⥐⥑⥒⥓⥔⥕⥖⥗⥘⥙⥚⥛⥜⥝⥞⥟⥠⥡⥢⥣⥤⥥⥦⥧⥨⥩⥪⥫⥬⥭⥮⥯⥰⥱⥲⥳⥴⥵⥶⥷⥸⥹⥺⥻⥼⥽⥾⥿➔➘➙➚➛➜➝➞➝➞➟➠➡➢➣➤➥➦➧➨➩➩➪➫➬➭➮➯➱➲➳➴➵➶➷➸➹➺➻➼➽➾⬀⬁⬂⬃⬄⬅⬆⬇⬈⬉⬊⬋⬌⬍⬎⬏⬐⬑☇☈⏎⍃⍄⍅⍆⍇⍈⍐⍗⍌⍓⍍⍔⍏⍖♾⎌☊☋☌☍⌃⌄⌤⌅⌆⌇⚋⚊⌌⌍⌎⌏⌐⌑⌔⌕⌗⌙⌢⌣⌯⌬⌭⌮⌖⌰⌱⌲⌳⌴⌵⌶⌷⌸⌹⌺⌻⌼⍯⍰⌽⌾⌿⍀⍁⍂⍉⍊⍋⍎⍏⍑⍒⍕⍖⍘⍙⍚⍛⍜⍝⍞⍠⍟⍡⍢⍣⍤⍥⍨⍩⍦⍧⍬⍿⍪⍮⍫⍱⍲⍭⍳⍴⍵⍶⍷⍸⍹⍺⍼⍽⍾⎀⎁⎂⎃⎄⎅⎆⎉⎊⎋⎍⎎⎏⎐⎑⎒⎓⎔⎕⏣⌓⏥⏢⎖⎲⎳⎴⎵⎶⎸⎹⎺⎻⎼⎽⎾⎿⏀⏁⏂⏃⏄⏅⏆⏇⏈⏉⏉⏋⏌⏍⏐⏤⏚⏛Ⓝℰⓦ!   ⌘«»‹›‘’“”„‚❝❞£¥€$¢¬¶@§®©™°×π±√‰Ω∞≈÷~≠¹²³½¼¾‐–—|⁄\[]{}†‡…·•●⌥⌃⇧↩¡¿‽⁂∴∵◊※←→↑↓☜☞☝☟✔★☆♺☼☂☺☹☃✉✿✄✈✌✎♠♦♣♥♪♫♯♀♂αßÁáÀàÅåÄäÆæÇçÉéÈèÊêÍíÌìÎîÑñÓóÒòÔôÖöØøÚúÙùÜüŽž₳฿￠€₡¢₢₵₫￡£₤₣ƒ₲₭₥₦₱＄$₮₩￦¥￥₴₰¤៛₪₯₠₧₨௹﷼㍐৲৳~ƻƼƽ¹¸¬¨ɂǁ¯Ɂǂ¡´°ꟾ¦}{|.,·])[/_\¿º§\"*-+(!&%$¼¾½¶©®@ẟⱿ`Ȿ^꜠꜡ỻ'=:;<ꞌꞋ꞊ꞁꞈ꞉>?÷ℾℿ℔℩℉⅀℈þðÞµªꝋꜿꜾⱽⱺⱹⱷⱶⱵⱴⱱⱰⱦȶȴȣȢȡȝȜțȋȊȉȈǯǮǃǀƿƾƺƹƸƷƲưƪƣƢƟƛƖƕƍſỽ⸀⸁⸂⸃⸄⸅⸆⸇⸈⸉⸊⸋⸌⸍⸎⸏⸐⸑⸒⸔⸕▲▼◀▶◢◣◥◤△▽◿◺◹◸▴▾◂▸▵▿◃▹◁▷◅▻◬⟁⧋⧊⊿∆∇◭◮⧩⧨⌔⟐◇◆◈⬖⬗⬘⬙⬠⬡⎔⋄◊⧫⬢⬣▰▪◼▮◾▗▖■∎▃▄▅▆▇█▌▐▍▎▉▊▋❘❙❚▀▘▝▙▚▛▜▟▞░▒▓▂▁▬▔▫▯▭▱◽□◻▢⊞⊡⊟⊠▣▤▥▦⬚▧▨▩⬓◧⬒◨◩◪⬔⬕❏❐❑❒⧈◰◱◳◲◫⧇⧅⧄⍁⍂⟡⧉○◌◍◎◯❍◉⦾⊙⦿⊜⊖⊘⊚⊛⊝●⚫⦁◐◑◒◓◔◕⦶⦸◵◴◶◷⊕⊗⦇⦈⦉⦊❨❩⸨⸩◖◗❪❫❮❯❬❭❰❱⊏⊐⊑⊒◘◙◚◛◜◝◞◟◠◡⋒⋓⋐⋑╰╮╭╯⌒╳✕╱╲⧸⧹⌓◦❖✖✚✜⧓⧗⧑⧒⧖_⚊╴╼╾‐⁃‑‒-–⎯—―╶╺╸─━┄┅┈┉╌╍═≣≡☰☱☲☳☴☵☶☷╵╷╹╻│▕▏┃┆┇┊╎┋╿╽┌┍┎┏┐┑┒┓└┕┖┗┘┙┚┛├┝┞┟┠┡┢┣┤┥┦┧┨┩┪┫┬┭┮┳┴┵┶┷┸┹┺┻┼┽┾┿╀╁╂╃╄╅╆╇╈╉╊╋╏║╔╒╓╕╖╗╚╘╙╛╜╝╞╟╠╡╢╣╤╥╦╧╨╩╪╫╬⌞⌟⌜⌝⌊⌋⌉⌈⌋₯ἀἁἂἃἄἅἆἇἈἉἊἋἌἍἎἏἐἑἒἓἔἕἘἙἚἛἜἝἠἡἢἣἤἥἦἧἨἩἪἫἬἭἮἯἰἱἲἳἴἵἶἷἸἹἺἻἼἽἾἿὀὁὂὃὄὅὈὉὊὋὌὍὐὑὒὓὔὕὖὗὙὛὝὟὠὡὢὣὤὥὦὧὨὩὪὫὬὭὮὯὰάὲέὴήὶίὸόὺύὼώᾀᾁᾂᾃᾄᾅᾆᾇᾈᾉᾊᾋᾌᾍᾎᾏᾐᾑᾒᾓᾔᾕᾖᾗᾘᾙᾚᾛᾜᾝᾞᾟᾠᾡᾢᾣᾤᾥᾦᾧᾨᾩᾪᾫᾬᾭᾮᾯᾰᾱᾲᾳᾴᾶᾷᾸᾹᾺΆᾼ᾽ι᾿῀῁ῂῃῄῆῇῈΈῊΉῌ῍῎῏ῐῑῒΐῖῗῘῙῚΊ῝῞῟ῠῡῢΰῤῥῦῧῨῩῪΎῬ῭΅`ῲῳῴῶῷῸΌῺΏῼ´῾ͰͱͲͳʹ͵Ͷͷͺͻͼͽ;΄΅Ά·ΈΉΊΌΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώϐϑϒϓϔϕϖϗϘϙϚϛϜϝϞϟϠϡϢϣϤϥϦϧϨϩϪϫϬϭϮϯϰϱϲϳϴϵ϶ϷϸϹϺϻϼϽϾϿⒶⓐ⒜AaẠạẢảḀḁÂÃǍǎẤấẦầẨẩȂȃẪẫẬậÀÁẮắẰằẲẳẴẵẶặĀāĄąǞȀȁÅǺǻÄäǟǠǡâáåãàẚȦȧȺÅⱥÆæǼǢǣⱯꜲꜳꜸꜺⱭꜹꜻª℀⅍℁Ⓑⓑ⒝BbḂḃḄḅḆḇƁɃƀƃƂƄƅℬⒸⓒ⒞CcḈḉĆćĈĉĊċČčÇçƇƈȻȼℂ℃ℭƆ℅℆℄ꜾꜿⒹⓓ⒟DdḊḋḌḍḎḏḐḑḒḓĎďƊƋƌƉĐđȡⅅⅆǱǲǳǄǅǆȸⒺⓔ⒠EeḔḕḖḗḘḙḚḛḜḝẸẹẺẻẾếẼẽỀềỂểỄễỆệĒēĔĕĖėĘęĚěÈèÉéÊêËëȄȅȨȩȆȇƎⱸɆℇℯ℮ƐℰƏǝⱻɇⒻⓕ⒡FfḞḟƑƒꜰℲⅎꟻℱ℻Ⓖⓖ⒢GgƓḠḡĜĝĞğĠġĢģǤǥǦǧǴℊ⅁ǵⒽⓗ⒣HhḢḣḤḥḦḧḨḩḪḫẖĤĥȞȟĦħⱧⱨꜦℍǶℏℎℋℌꜧⒾⓘ⒤IiḬḭḮḯĲĳìíîïÌÍÎÏĨĩĪīĬĭĮįıƗƚỺǏǐⅈⅉℹℑℐⒿⓙ⒥JjĴĵȷⱼɈɉǰⓀⓚ⒦KkḰḱḲḳḴḵĶķƘƙꝀꝁꝂꝃꝄꝅǨǩⱩⱪĸⓁⓛ⒧LlḶḷḸḹḺḻḼḽĹĺĻļĽİľĿŀŁłỈỉỊịȽⱠꝈꝉⱡⱢꞁℒǇǈǉ⅃⅂ℓȉȈȊȋⓂⓜ⒨MmḾḿṀṁṂṃꟿꟽⱮƩƜℳⓃⓝ⒩NnṄṅṆṇṈṉṊṋŃńŅņŇňǸǹŊƝñŉÑȠƞŋǊǋǌȵℕ№OoṌṍṎṏṐṑṒṓȪȫȬȭȮȯȰȱǪǫǬǭỌọỎỏỐốỒồỔổỖỗỘộỚớỜờỞởỠỡỢợƠơŌōŎŏŐőÒÓÔÕÖǑȌȍȎȏŒœØǾꝊǽǿℴ⍥⍤Ⓞⓞ⒪òóôõöǒøꝎꝏⓅⓟ⒫℗PpṔṕṖṗƤƥⱣℙǷꟼ℘Ⓠⓠ⒬QqɊɋℚ℺ȹⓇⓡ⒭RrŔŕŖŗŘřṘṙṚṛṜṝṞṟȐȑȒȓɍɌƦⱤ℞Ꝛꝛℜℛ℟ℝⓈⓢ⒮SsṠṡṢṣṤṥṦṧṨṩŚśŜŝŞşŠšȘșȿꜱƧƨẞßẛẜẝ℠Ⓣⓣ⒯TtṪṫṬṭṮṯṰṱŢţŤťŦŧƬƮẗȚȾƫƭțⱦȶ℡™Ⓤⓤ⒰UuṲṳṴṵṶṷṸṹṺṻỤỦủỨỪụứỬửừữỮỰựŨũŪūŬŭŮůŰűǙǚǗǘǛǜŲųǓǔȔȕÛûȖȗÙùÜüƯúɄưƲƱⓋⓥ⒱VvṼṽṾṿỼɅ℣ⱱⱴⱽⓌⓦ⒲WwẀẁẂẃẄẅẆẇẈẉŴŵẘⱲⱳⓍⓧ⒳XxẊẋẌẍℵ×Ⓨⓨ⒴yYẎẏỾỿẙỲỳỴỵỶỷỸỹŶŷƳƴŸÿÝýɎɏȲƔ⅄ȳℽⓏⓩ⒵ZzẐẑẒẓẔẕŹźŻżŽžȤȥⱫⱬƵƶɀℨℤ⟀⟁⟂⟃⟄⟇⟈⟉⟊⟐⟑⟒⟓⟔⟕⟖⟗⟘⟙⟚⟛⟜⟝⟞⟟⟠⟡⟢⟣⟤⟥⟦⟧⟨⟩⟪⟫⦀⦁⦂⦃⦄⦅⦆⦇⦈⦉⦊⦋⦌⦍⦎⦏⦐⦑⦒⦓⦔⦕⦖⦗⦘⦙⦚⦛⦜⦝⦞⦟⦠⦡⦢⦣⦤⦥⦦⦧⦨⦩⦪⦫⦬⦭⦮⦯⦰⦱⦲⦳⦴⦵⦶⦷⦸⦹⦺⦻⦼⦽⦾⦿⧀⧁⧂⧃⧄⧅⧆⧇⧈⧉⧊⧋⧌⧍⧎⧏⧐⧑⧒⧓⧔⧕⧖⧗⧘⧙⧚⧛⧜⧝⧞⧟⧡⧢⧣⧤⧥⧦⧧⧨⧩⧪⧫⧬⧭⧮⧯⧰⧱⧲⧳⧴⧵⧶⧷⧸⧹⧺⧻⧼⧽⧾⧿∀∁∂∃∄∅∆∇∈∉∊∋∌∍∎∏∐∑−∓∔∕∖∗∘∙√∛∜∝∞∟∠∡∢∣∤∥∦∧∨∩∪∫∬∭∮∯∰∱∲∳∴∵∶∷∸∹∺∻∼∽∾∿≀≁≂≃≄≅≆≇≈≉≊≋≌≍≎≏≐≑≒≓≔≕≖≗≘≙≚≛≜≝≞≟≠≡≢≣≤≥≦≧≨≩≪≫≬≭≮≯≰≱≲≳≴≵≶≷≸≹≺≻≼≽≾≿⊀⊁⊂⊃⊄⊅⊆⊇⊈⊉⊊⊋⊌⊍⊎⊏⊐⊑⊒⊓⊔⊕⊖⊗⊘⊙⊚⊛⊜⊝⊞⊟⊠⊡⊢⊣⊤⊥⊦⊧⊨⊩⊪⊫⊬⊭⊮⊯⊰⊱⊲⊳⊴⊵⊶⊷⊸⊹⊺⊻⊼⊽⊾⊿⋀⋁⋂⋃⋄⋅⋆⋇⋈⋉⋊⋋⋌⋍⋎⋏⋐⋑⋒⋓⋔⋕⋖⋗⋘⋙⋚⋛⋜⋝⋞⋟⋠⋡⋢⋣⋤⋥⋦⋧⋨⋩⋪⋫⋬⋭⋮⋯⋰⋱⋲⋳⋴⋵⋶⋷⋸⋹⋺⋻⋼⋽⋾⋿✕✖✚◀▶❝❞★☆☼☂☺☹✄✈✌✎♪♫☀☁☔⚡❆☽☾✆✔☯☮☠⚑☬✄✏♰✡✰✺⚢⚣♕♛♚♬ⓐⓑⓒⓓ↺↻⇖⇗⇘⇙⟵⟷⟶⤴⤵⤶⤷➫➬€₤＄₩₪⟁⟐◆⎔░▢⊡▩⟡◎◵⊗❖ΩβΦΣΞ⟁⦻⧉⧭⧴∞≌⊕⋍⋰⋱✖⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾ᴕ⸨⸩❪❫⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾⒈⒉⒊⒋⒌⒍⒎⒏⒐⒑⒒⒓⒔⒕⒖⒗⒘⒙⒚⒛⓪①②③④⑤⑥⑦⑧⑨⑩➀➁➂➃➄➅➆➇➈➉⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳⓿❶❷❸❹❺❻❼❽❾❿➊➋➌➍➎➏➐➑➒➓⓫⓬⓭⓮⓯⓰⓱⓲⓳⓴⑴⑵⑶⑷⑸⑹⑺⑻⑼⑽⑾⑿⒀⒁⒂⒃⒄⒅⒆⒇ᶅᶛᶜᶝᶞᶟᶠᶡᶢᶣᶤᶥᶦᶧᶨᶩᶪᶫᶬᶭᶮᶯᶰᶱᶲᶳᶴᶵᶶᶷᶹᶺᶻᶼᶽᶾᶿᴀᴁᴂᴃᴄᴅᴆᴇᴈᴉᴊᴋᴌᴍᴎᴏᴐᴑᴒᴓᴔᴕᴖᴗᴘᴙᴚᴛᴜᴝᴞᴟᴠᴡᴢᴣᴤᴥᴦᴧᴨᴩᴪᴫᴬᴭᴮᴯᴰᴱᴲᴳᴴᴵᴶᴷᴸᴹᴺᴻᴼᴽᴾᴿᵀᵁᵂᵃᵄᵅᵆᵇᵈᵉᵊᵋᵌᵍᵎᵏᵐᵑᵒᵓᵔᵕᵖᵗᵘᵙᵚᵛᵜᵝᵞᵟᵠᵡᵢᵣᵤᵥᵦᵧᵨᵩᵪᵫᵬᵭᵮᵱᵲᵳᵵᵷᵸᵺᵻ᷎᷏᷋᷌ᷓᷔᷕᷖᷗᷘᷙᷛᷜᷝᷞᷟᷠᷡᷢᷣᷤᷥᷦ᷍‘’‛‚“”„‟«»‹›Ꞌ❛❜❝❞<>@‧¨․꞉:⁚⁝⁞‥…⁖⸪⸬⸫⸭⁛⁘⁙⁏;⦂⁃‐‑‒-–⎯—―_⁓⸛⸞⸟ⸯ¬/\⁄\⁄|⎜¦‖‗†‡·•⸰°‣⁒%‰‱&⅋§÷+±=꞊′″‴⁗‵‶‷‸*⁑⁎⁕※⁜⁂!‼¡?¿⸮⁇⁉⁈‽⸘¼½¾²³©®™℠℻℅℁⅍℄¶⁋❡⁌⁍⸖⸗⸚⸓()[]{}⸨⸩❨❩❪❫⸦⸧❬❭❮❯❰❱❴❵❲❳⦗⦘⁅⁆〈〉⏜⏝⏞⏟⸡⸠⸢⸣⸤⸥⎡⎤⎣⎦⎨⎬⌠⌡⎛⎠⎝⎞⁀⁔‿⁐‾⎟⎢⎥⎪ꞁ⎮⎧⎫⎩⎭⎰⎱✈☀☼☁☂☔⚡❄❅❆☃☉☄★☆☽☾⌛⌚☇☈⌂⌁✆☎☏☑✓✔⎷⍻✖✗✘☒✕☓☕♿✌☚☛☜☝☞☟☹☺☻☯⚘☮✝⚰⚱⚠☠☢⚔⚓⎈⚒⚑⚐☡❂⚕⚖⚗✇☣⚙☤⚚⚛⚜☥☦☧☨☩†☪☫☬☭✁✂✃✄✍✎✏✐✑✒✉✙✚✜✛♰♱✞✟✠✡☸✢✣✤✥✦✧✩✪✫✬✭✮✯✰✲✱✳✴✵✶✷✸✹✺✻✼✽✾❀✿❁❃❇❈❉❊❋⁕☘❦❧☙❢❣♀♂⚢⚣⚤⚦⚧⚨⚩☿♁⚯♔♕♖♗♘♙♚♛♜♝♞♟☖☗♠♣♦♥❤❥♡♢♤♧⚀⚁⚂⚃⚄⚅⚇⚆⚈⚉♨♩♪♫♬♭♮♯⌨⏏⎗⎘⎙⎚⌥⎇⌘⌦⌫⌧♲♳♴♵♶♷♸♹♺♻♼♽⁌⁍⎌⌇⌲⍝⍟⍣⍤⍥⍨⍩⎋♃♄♅♆♇♈♉♊♋♌♍♎♏♐♑♒♓⏚⏛​|",
                    suffix,
                )
            if trouble_type == 'LONG_TEXT':
                return '{}{}{}'.format(
                    prefix,
                    self.randomString(len=256, prefix=""),
                    suffix,
                )
            if trouble_type == 'VERY_LONG_TEXT':
                return '{}{}{}'.format(
                    prefix,
                    self.randomString(len=65536, prefix=""),
                    suffix,
                )
            if trouble_type == 'EXTREMELY_LONG_TEXT':
                return '{}{}{}'.format(
                    prefix,
                    self.randomString(len=16777216, prefix=""),
                    suffix,
                )
            if trouble_type == 'TOOOO_LONG_TEXT':
                return '{}{}{}'.format(
                    prefix,
                    self.randomString(len=4294967296, prefix=""),
                    suffix,
                )

        if trouble_type == 'UNEXPECTED_OPTION':
            return self.randomString()

        self.assertFalse("Unexpected trouble: {}".format(trouble_type))
        return data
