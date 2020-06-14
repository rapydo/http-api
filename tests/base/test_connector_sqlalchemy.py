import os
import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "sqlalchemy"


def test_sqlalchemy(app):

    if not detector.check_availability(CONNECTOR):

        obj = detector.get_debug_instance(CONNECTOR)
        assert obj is None

        log.warning("Skipping sqlalchemy test: service not available")
        return False

    detector.init_services(
        app=app, project_init=False, project_clean=False,
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
            CONNECTOR, test_connection=True, user="invaliduser",
        )

        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    obj = detector.get_service_instance(CONNECTOR, test_connection=True,)
    assert obj is not None

    obj = detector.get_service_instance(
        CONNECTOR, cache_expiration=1, test_connection=True
    )
    obj_id = id(obj)

    obj = detector.get_service_instance(
        CONNECTOR, cache_expiration=1, test_connection=True
    )
    assert id(obj) == obj_id

    time.sleep(1)

    obj = detector.get_service_instance(
        CONNECTOR, cache_expiration=1, test_connection=True
    )
    # With alchemy the connection object remain the same...
    assert id(obj) == obj_id
    # assert id(obj) != obj_id

    # Close connection...
    obj.disconnect()

    # test connection... and should fail
    # ???

    # ... close connection again ... nothing should happens
    obj.disconnect()

    # sqlalchemy connector does not support with context
    # with detector.get_service_instance(CONNECTOR) as obj:
    #     assert obj is not None

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_debug_instance("invalid")
    assert obj is None
