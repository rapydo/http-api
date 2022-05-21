import time

import pytest
from flask import Flask

from restapi.connectors import Connector
from restapi.connectors import sqlalchemy as connector
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log

CONNECTOR = "sqlalchemy"
CONNECTOR_AVAILABLE = Connector.check_availability(CONNECTOR)


@pytest.mark.skipif(
    CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be not available"
)
def test_no_sqlalchemy() -> None:

    with pytest.raises(ServiceUnavailable):
        connector.get_instance()

    log.warning("Skipping {} tests: service not available", CONNECTOR)
    return None


@pytest.mark.skipif(
    not CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be available"
)
def test_sqlalchemy(app: Flask) -> None:

    log.info("Executing {} tests", CONNECTOR)

    if not connector.SQLAlchemy.is_mysql():
        with pytest.raises(ServiceUnavailable):
            connector.get_instance(host="invalidhostname", port="123")

    with pytest.raises(ServiceUnavailable):
        connector.get_instance(user="invaliduser")

    obj = connector.get_instance()
    assert obj is not None

    with pytest.raises(AttributeError, match=r"Model InvalidModel not found"):
        obj.InvalidModel

    obj.disconnect()

    # a second disconnect should not raise any error
    obj.disconnect()

    # Create new connector with short expiration time
    obj = connector.get_instance(expiration=2, verification=1)
    obj_id = id(obj)
    obj_db_id = id(obj.db)

    # Connector is expected to be still valid
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) == obj_id

    time.sleep(1)

    # The connection should have been checked and should be still valid
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) == obj_id

    time.sleep(1)

    obj = connector.get_instance(expiration=2, verification=1)
    # With alchemy the connection object remains the same...
    assert id(obj) != obj_id
    assert id(obj.db) == obj_db_id

    assert obj.is_connected()
    obj.disconnect()
    assert not obj.is_connected()

    # ... close connection again ... nothing should happen
    obj.disconnect()

    # sqlalchemy connector does not support with context
    # with connector.get_instance() as obj:
    #     assert obj is not None
