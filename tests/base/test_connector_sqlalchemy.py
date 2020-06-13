import os
import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_sqlalchemy(app):

    if not detector.check_availability("sqlalchemy"):
        log.warning("Skipping sqlalchemy test: service not available")
        return False

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    if os.getenv("ALCHEMY_DBTYPE") != "mysql+pymysql":
        try:
            detector.get_service_instance(
                "sqlalchemy", test_connection=True, host="invalidhostname", port=123
            )

            pytest.fail("No exception raised on unavailable service")
        except ServiceUnavailable:
            pass

    try:
        detector.get_service_instance(
            "sqlalchemy", test_connection=True, user="invaliduser",
        )

        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    sql = detector.get_service_instance("sqlalchemy", test_connection=True,)
    assert sql is not None

    sql = detector.get_service_instance(
        "sqlalchemy", cache_expiration=1, test_connection=True
    )
    obj_id = id(sql)

    sql = detector.get_service_instance(
        "sqlalchemy", cache_expiration=1, test_connection=True
    )
    assert id(sql) == obj_id

    time.sleep(1)

    sql = detector.get_service_instance(
        "sqlalchemy", cache_expiration=1, test_connection=True
    )
    # With alchemy the connection object remain the same...
    assert id(sql) == obj_id
    # assert id(sql) != obj_id

    # Close connection...
    sql.disconnect()

    # test connection... and should fail
    # ???

    # ... close connection again ... nothing should happens
    sql.disconnect()

    with detector.get_service_instance("sqlalchemy") as obj:
        assert obj is not None
