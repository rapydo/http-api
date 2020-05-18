# -*- coding: utf-8 -*-
# from datetime import datetime

from restapi.utilities.processes import find_process
# from restapi.utilities.processes import wait_socket
from restapi.tests import BaseTests
from restapi.utilities.meta import Meta
from restapi.utilities.logs import handle_log_output, obfuscate_dict
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.time import date_from_string
from restapi.services.mail import send as _send_mail


class TestApp(BaseTests):
    def test_libs(self):

        assert not find_process("this-should-not-exist")
        s = Meta.get_submodules_from_package(None)
        assert isinstance(s, list)
        assert len(s) == 0

        s = handle_log_output(None)
        assert isinstance(s, dict)
        assert len(s) == 0

        s = handle_log_output(" ")
        assert isinstance(s, dict)
        assert len(s) == 0

        # obfuscate_dict only accepts dict
        assert obfuscate_dict(None) is None
        assert obfuscate_dict(10) == 10
        assert obfuscate_dict(['x']) == ['x']
        assert len(obfuscate_dict({})) == 0
        assert obfuscate_dict({"x": "y"}) == {"x": "y"}
        assert obfuscate_dict({"password": "y"}) == {"password": "****"}
        assert obfuscate_dict({"pwd": "y"}) == {"pwd": "****"}
        assert obfuscate_dict({"token": "y"}) == {"token": "****"}
        assert obfuscate_dict({"access_token": "y"}) == {"access_token": "****"}
        assert obfuscate_dict({"file": "y"}) == {"file": "****"}
        assert obfuscate_dict({"filename": "y"}) == {"filename": "****"}
        assert obfuscate_dict({"new_password": "y"}) == {"new_password": "****"}
        assert obfuscate_dict({"password_confirm": "y"}) == {"password_confirm": "****"}

        assert hcodes.HTTP_CONTINUE == 100
        assert hcodes.HTTP_SWITCHING_PROTOCOLS == 101
        assert hcodes.HTTP_OK_BASIC == 200
        assert hcodes.HTTP_OK_CREATED == 201
        assert hcodes.HTTP_OK_ACCEPTED == 202
        assert hcodes.HTTP_OK_NORESPONSE == 204
        assert hcodes.HTTP_PARTIAL_CONTENT == 206
        assert hcodes.HTTP_MULTIPLE_CHOICES == 300
        assert hcodes.HTTP_FOUND == 302
        assert hcodes.HTTP_NOT_MODIFIED == 304
        assert hcodes.HTTP_TEMPORARY_REDIRECT == 307
        assert hcodes.HTTP_BAD_REQUEST == 400
        assert hcodes.HTTP_BAD_UNAUTHORIZED == 401
        assert hcodes.HTTP_BAD_FORBIDDEN == 403
        assert hcodes.HTTP_BAD_NOTFOUND == 404
        assert hcodes.HTTP_BAD_METHOD_NOT_ALLOWED == 405
        assert hcodes.HTTP_BAD_CONFLICT == 409
        assert hcodes.HTTP_BAD_RESOURCE == 410
        assert hcodes.HTTP_BAD_PAYLOAD_TOO_LARGE == 413
        assert hcodes.HTTP_BAD_RANGE_NOT_SATISFIABLE == 416
        assert hcodes.HTTP_SERVER_ERROR == 500
        assert hcodes.HTTP_NOT_IMPLEMENTED == 501
        assert hcodes.HTTP_SERVICE_UNAVAILABLE == 503
        assert hcodes.HTTP_INTERNAL_TIMEOUT == 504

        assert date_from_string(None) == ""
        assert date_from_string("") == ""
        # d = date_from_string("1/1/1970")
        # assert isinstance(d, datetime)

        assert not _send_mail("body", "subject", "to_address", "from_address", None)
        assert not _send_mail("body", "subject", "to_address", None, "locahost")
        assert not _send_mail("body", "subject", None, "from_address", "locahost")

        assert not _send_mail(
            "body", "subject", "to_address", "from_address", "locahost", smtp_port="x")

        # standard port
        assert _send_mail(
            "body", "subject", "to_address", "from_address", "locahost")
        # local server (no port)
        assert _send_mail(
            "body", "subject", "to_address", "from_address", "locahost", smtp_port=None)
        # TLS port
        assert _send_mail(
            "body", "subject", "to_address", "from_address", "locahost", smtp_port=465)

        mail = self.read_mock_email()
        body = mail.get('body')
        headers = mail.get('headers')
        assert body is not None
        assert headers is not None
        # Subject: is a key in the MIMEText
        assert 'Subject: subject' in headers
        assert mail.get('from') == "from_address"
        assert mail.get('cc') == ['to_address']
        assert mail.get('bcc') is None

        assert _send_mail(
            "body", "subject", "to_address", "from_address", "locahost",
            cc="test1", bcc="test2"
        )

        mail = self.read_mock_email()
        body = mail.get('body')
        headers = mail.get('headers')
        assert body is not None
        assert headers is not None
        # Subject: is a key in the MIMEText
        assert 'Subject: subject' in headers
        assert mail.get('from') == "from_address"
        # format is [to, [cc...], [bcc...]]
        assert mail.get('cc') == ['to_address', ['test1'], ['test2']]

        assert _send_mail(
            "body", "subject", "to_address", "from_address", "locahost",
            cc=["test1", "test2"], bcc=["test3", "test4"]
        )

        mail = self.read_mock_email()
        body = mail.get('body')
        headers = mail.get('headers')
        assert body is not None
        assert headers is not None
        # Subject: is a key in the MIMEText
        assert 'Subject: subject' in headers
        assert mail.get('from') == "from_address"
        # format is [to, [cc...], [bcc...]]
        assert mail.get('cc') == ['to_address', ['test1', "test2"], ['test3', "test4"]]
