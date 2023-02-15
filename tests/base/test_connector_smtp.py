import time
from unittest.mock import patch

import pytest
from faker import Faker
from flask import Flask

from restapi.connectors import Connector
from restapi.connectors import smtp as connector
from restapi.exceptions import ServiceUnavailable
from restapi.tests import BaseTests
from restapi.utilities.logs import log

CONNECTOR = "smtp"
CONNECTOR_AVAILABLE = Connector.check_availability(CONNECTOR)


# mailmock is always enabled during core tests
@pytest.mark.skipif(
    CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be not available"
)
def test_no_smtp() -> None:  # pragma: no cover
    with pytest.raises(ServiceUnavailable):
        connector.get_instance()

    log.warning("Skipping {} tests: service not available", CONNECTOR)
    return None


@pytest.mark.skipif(
    not CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be available"
)
def test_smtp(app: Flask, faker: Faker) -> None:
    obj = connector.get_instance()
    assert obj is not None
    assert obj.smtp is not None

    obj = connector.get_instance(port="465")
    assert obj is not None
    assert obj.smtp is not None

    obj = connector.get_instance(port="587")
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
    assert mail.get("cc") == ["to_addr", "test1", "test2", "test3", "test4"]

    # This is a special from_address, used to raise SMTPException
    assert not obj.send("body", "subject", "to_addr", "invalid1")
    # This is a special from_address, used to raise Exception
    obj = connector.get_instance()
    assert not obj.send("body", "subject", "to_addr", "invalid2")
    # This is NOT a special from_address
    obj = connector.get_instance()
    assert obj.send("body", "subject", "to_addr", "invalid3")

    # Test that cc and bcc with wrong types are ignored
    assert obj.send(
        "body",
        "subject",
        "to_addr",
        "from_addr",
        cc=10,  # type: ignore
        bcc=20,  # type: ignore
    )

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

    with connector.get_instance(noreply="", admin="") as obj:
        assert not obj.send("body", "subject")
        assert not obj.send("body", "subject", "to_addr")
        assert obj.send("body", "subject", "to_addr", "from_addr")

    obj = connector.get_instance()
    assert obj.is_connected()
    obj.disconnect()

    # a second disconnect should not raise any error
    obj.disconnect()

    assert not obj.is_connected()

    with pytest.raises(ServiceUnavailable, match=r"Invalid retry value: 0"):
        connector.get_instance(retries=0, retry_wait=0)
    with pytest.raises(ServiceUnavailable, match=r"Invalid retry value: -1"):
        connector.get_instance(retries=-1, retry_wait=0)
    with pytest.raises(ServiceUnavailable, match=r"Invalid retry wait value: -1"):
        connector.get_instance(retries=1, retry_wait=-1)
    obj = connector.get_instance(retries=1, retry_wait=0)
    assert obj is not None

    MOCKED_RETURN = connector.get_instance()
    # Clean the cache
    Connector.disconnect_all()
    WAIT = 1
    with patch.object(Connector, "initialize_connection") as mock:
        start = time.time()
        mock.side_effect = [
            ServiceUnavailable("first"),
            ServiceUnavailable("second"),
            MOCKED_RETURN,
        ]
        obj = connector.get_instance(retries=10, retry_wait=WAIT)

        assert mock.call_count == 3
        assert obj == MOCKED_RETURN
        end = time.time()

        assert end - start > WAIT
