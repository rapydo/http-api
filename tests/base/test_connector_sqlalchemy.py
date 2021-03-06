import time

import pytest
from flask import Flask

from restapi.connectors import Connector
from restapi.connectors import sqlalchemy as connector
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log

CONNECTOR = "sqlalchemy"


def test_sqlalchemy(app: Flask) -> None:

    if not Connector.check_availability(CONNECTOR):

        try:
            obj = connector.get_instance()
            pytest.fail("No exception raised")  # pragma: no cover
        except ServiceUnavailable:
            pass

        log.warning("Skipping {} tests: service not available", CONNECTOR)
        return None

    log.info("Executing {} tests", CONNECTOR)

    if not connector.SQLAlchemy.is_mysql():
        try:
            connector.get_instance(host="invalidhostname", port=123)

            pytest.fail(
                "No exception raised on unavailable service"
            )  # pragma: no cover
        except ServiceUnavailable:
            pass

    try:
        connector.get_instance(user="invaliduser")

        pytest.fail("No exception raised on unavailable service")  # pragma: no cover
    except ServiceUnavailable:
        pass

    obj = connector.get_instance()
    assert obj is not None

    try:
        obj.InvalidModel
        pytest.fail("No exception raised on InvalidModel")  # pragma: no cover
    except AttributeError as e:
        assert str(e) == "Model InvalidModel not found"

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

    # ... close connection again ... nothing should happens
    obj.disconnect()

    # sqlalchemy connector does not support with context
    # with connector.get_instance() as obj:
    #     assert obj is not None
