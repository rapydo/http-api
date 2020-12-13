import pytest

from restapi.connectors import smtp as connector
from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.tests import BaseTests
from restapi.utilities.logs import log

CONNECTOR = "smtp"


def test_smtp(app, faker):

    # mailmock is always enabled during core tests
    if not detector.check_availability(CONNECTOR):  # pragma: no cover

        try:
            obj = connector.get_instance()
            pytest.fail("No exception raised")  # pragma: no cover
        except ServiceUnavailable:
            pass

        log.warning("Skipping {} tests: service not available", CONNECTOR)
        return False

    detector.init_services(
        app=app,
        project_init=False,
        project_clean=False,
    )

    # try:
    #     connector.get_instance(host="invalidhostname", port=123)
    #     pytest.fail("No exception raised on unavailable service")  # pragma: no cover
    # except ServiceUnavailable:
    #     pass

    obj = connector.get_instance()
    assert obj is not None
    assert obj.smtp is not None

    obj = connector.get_instance(port=465)
    assert obj is not None
    assert obj.smtp is not None

    obj = connector.get_instance(port=587)
    assert obj is not None
    assert obj.smtp is not None

    assert obj.send("body", "subject")
    assert obj.send("body", "subject", "to_addr")
    assert obj.send("body", "subject", "to_addr", "from_addr")

    obj = connector.get_instance()

    mail = BaseTests.read_mock_email()
    body = mail.get("body")
    headers = mail.get("headers")
    assert body is not None
    assert headers is not None
    # Subject: is a key in the MIMEText
    assert "Subject: subject" in headers
    assert mail.get("from") == "from_addr"
    assert mail.get("cc") == ["to_addr"]
    assert mail.get("bcc") is None

    assert obj.send("body", "subject", "to_addr", "from_addr", cc="test1", bcc="test2")

    mail = BaseTests.read_mock_email()
    body = mail.get("body")
    headers = mail.get("headers")
    assert body is not None
    assert headers is not None
    # Subject: is a key in the MIMEText
    assert "Subject: subject" in headers
    assert mail.get("from") == "from_addr"
    # format is [to, [cc...], [bcc...]]
    assert mail.get("cc") == ["to_addr", ["test1"], ["test2"]]

    assert obj.send(
        "body",
        "subject",
        "to_addr",
        "from_addr",
        cc=["test1", "test2"],
        bcc=["test3", "test4"],
    )

    mail = BaseTests.read_mock_email()
    body = mail.get("body")
    headers = mail.get("headers")
    assert body is not None
    assert headers is not None
    # Subject: is a key in the MIMEText
    assert "Subject: subject" in headers
    assert mail.get("from") == "from_addr"
    # format is [to, [cc...], [bcc...]]
    assert mail.get("cc") == ["to_addr", ["test1", "test2"], ["test3", "test4"]]

    # This is a special from_address, used to raise SMTPException
    assert not obj.send("body", "subject", "to_addr", "invalid1")
    # This is a special from_address, used to raise BaseException
    assert not obj.send("body", "subject", "to_addr", "invalid2")
    # This is NOT a special from_address
    assert obj.send("body", "subject", "to_addr", "invalid3")

    assert obj.send("body", "subject", "to_addr", "from_addr", cc=10, bcc=20)

    mail = BaseTests.read_mock_email()
    body = mail.get("body")
    headers = mail.get("headers")
    assert body is not None
    assert headers is not None
    # Subject: is a key in the MIMEText
    assert "Subject: subject" in headers
    # cc and bcc with wrong type (int in this case!) are ignored
    assert mail.get("from") == "from_addr"
    # format is [to, [cc...], [bcc...]]
    assert mail.get("cc") == ["to_addr"]

    with connector.get_instance() as obj:
        assert obj is not None
        assert obj.smtp is not None
    # assert obj.smtp is None

    with connector.get_instance(noreply=None, admin=None) as obj:
        assert not obj.send("body", "subject")
        assert not obj.send("body", "subject", "to_addr")
        assert obj.send("body", "subject", "to_addr", "from_addr")

    obj = connector.get_instance()
    assert obj.is_connected()
    obj.disconnect()

    # a second disconnect should not raise any error
    obj.disconnect()

    assert not obj.is_connected()
