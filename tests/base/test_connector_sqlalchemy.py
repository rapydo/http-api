import os
import time

import pytest

from restapi.connectors import sqlalchemy as connector
from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "sqlalchemy"


def test_sqlalchemy(app):

    if not detector.check_availability(CONNECTOR):

        obj = detector.get_debug_instance(CONNECTOR)
        assert obj is None

        try:
            obj = connector.get_instance()
            pytest.fail("No exception raised")
        except ServiceUnavailable:
            pass

        log.warning("Skipping {} tests: service not available", CONNECTOR)
        return False

    log.info("Executing {} tests", CONNECTOR)

    # Run this before the init_services,
    # get_debug_instance is able to load what is needed
    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    detector.init_services(
        app=app,
        project_init=False,
        project_clean=False,
    )

    if os.getenv("ALCHEMY_DBTYPE") != "mysql+pymysql":
        try:
            detector.get_service_instance(
                CONNECTOR, test_connection=True, host="invalidhostname", port=123
            )

            pytest.fail("No exception raised on unavailable service")
        except ServiceUnavailable:
            pass

    try:
        detector.get_service_instance(
            CONNECTOR,
            test_connection=True,
            user="invaliduser",
        )

        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    obj = detector.get_service_instance(
        CONNECTOR,
        test_connection=True,
    )
    assert obj is not None

    obj = connector.get_instance(expiration=1, test_connection=True)
    obj_id = id(obj)
    obj_db_id = id(obj.db)

    obj = connector.get_instance(expiration=1, test_connection=True)
    assert id(obj) == obj_id

    time.sleep(1)

    obj = connector.get_instance(expiration=1, test_connection=True)
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

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_debug_instance("invalid")
    assert obj is None
