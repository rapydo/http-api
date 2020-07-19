import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.tests import BaseTests
from restapi.utilities.logs import log

CONNECTOR = "smtp"


def test_smtp(app, faker):

    if not detector.check_availability(CONNECTOR):

        obj = detector.get_debug_instance(CONNECTOR)
        assert obj is None

        try:
            obj = detector.get_service_instance(CONNECTOR)
            pytest("No exception raised")
        except ServiceUnavailable:
            pass

        log.warning("Skipping {} tests: service not available", CONNECTOR)
        return False

    # Run this before the init_services,
    # get_debug_instance is able to load what is needed
    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    # try:
    #     detector.get_service_instance(CONNECTOR, host="invalidhostname", port=123)
    #     pytest.fail("No exception raised on unavailable service")
    # except ServiceUnavailable:
    #     pass

    obj = detector.get_service_instance(CONNECTOR)
    assert obj is not None
    assert obj.smtp is not None

    obj = detector.get_service_instance(CONNECTOR, port=465)
    assert obj is not None
    assert obj.smtp is not None

    obj = detector.get_service_instance(CONNECTOR, port=587)
    assert obj is not None
    assert obj.smtp is not None

    assert obj.send("body", "subject")
    assert obj.send("body", "subject", "to_addr")
    assert obj.send("body", "subject", "to_addr", "from_addr")

    obj = detector.get_service_instance(CONNECTOR)

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

    with detector.get_service_instance(CONNECTOR) as obj:
        assert obj is not None
        assert obj.smtp is not None
    assert obj.smtp is None

    with detector.get_service_instance(CONNECTOR, noreply=None, admin=None) as obj:
        assert not obj.send("body", "subject")
        assert not obj.send("body", "subject", "to_addr")
        assert obj.send("body", "subject", "to_addr", "from_addr")
