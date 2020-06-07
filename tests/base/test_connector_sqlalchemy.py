import os

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
