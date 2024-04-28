import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from faker import Faker
from flask import Flask

from restapi.connectors import Connector
from restapi.connectors import ftp as connector
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log

CONNECTOR = "ftp"
CONNECTOR_AVAILABLE = Connector.check_availability(CONNECTOR)


@pytest.mark.skipif(
    CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be not available"
)
def test_no_ftp() -> None:
    with pytest.raises(ServiceUnavailable):
        connector.get_instance()

    log.warning("Skipping {} tests: service not available", CONNECTOR)
    return None


@pytest.mark.skipif(
    not CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be available"
)
def test_ftp(app: Flask, faker: Faker) -> None:
    log.info("Executing {} tests", CONNECTOR)

    with pytest.raises(ServiceUnavailable):
        connector.get_instance(host="invalidhostname", port="123")

    obj = connector.get_instance()
    assert obj is not None
    assert obj.is_connected()

    obj.disconnect()
    assert not obj.is_connected()

    # a second disconnect should not raise any error
    obj.disconnect()

    # Create new connector with short expiration time
    obj = connector.get_instance(expiration=2, verification=1)
    obj_id = id(obj)

    # Connector is expected to be still valid
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) == obj_id

    time.sleep(1)

    # The connection should have been checked and should be still valid
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) == obj_id

    time.sleep(1)

    # Connection should have been expired and a new connector been created
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) != obj_id

    assert obj.is_connected()
    obj.disconnect()
    assert not obj.is_connected()

    # ... close connection again ... nothing should happen
    obj.disconnect()

    with connector.get_instance() as obj:
        assert obj is not None

        # The FTP folder is empty => only . and .. are returned
        assert len(list(obj.connection.mlsd())) == 2

        # Upload a random content file on the FTP
        tmp_content = faker.pystr()
        ftp_filename = faker.file_name()
        tmp_path = tempfile.NamedTemporaryFile().name

        with open(tmp_path, "w+") as temporary_write_file:
            temporary_write_file.write(tmp_content)

        with open(tmp_path, "rb") as temporary_read_file:
            # or storbinary for binary mode
            obj.connection.storlines(f"STOR {ftp_filename}", temporary_read_file)

        assert len(list(obj.connection.mlsd())) == 3

        # Download the file and verify it matches
        download_file: Path = Path(tempfile.NamedTemporaryFile().name)

        with open(download_file, "w") as download_handle:
            # Command for Downloading the file "RETR filename"
            # or retrbinary for binary mode
            obj.connection.retrlines(f"RETR {ftp_filename}", download_handle.write)

        with open(download_file) as download_handle:
            downloaded_content = download_handle.read()
            assert downloaded_content == tmp_content

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
