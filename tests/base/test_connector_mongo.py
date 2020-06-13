import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_mongo(app):

    if not detector.check_availability("mongo"):
        log.warning("Skipping mongo test: service not available")
        return False

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    try:
        mongo = detector.get_service_instance(
            "mongo", test_connection=True, host="invalidhostname", port=123
        )
        # test_connection does not work, let's explicitly test it
        try:
            mongo.Token.objects.first()
        except BaseException:
            raise ServiceUnavailable("")
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    mongo = detector.get_service_instance("mongo", test_connection=True,)
    assert mongo is not None

    mongo = detector.get_service_instance("mongo", cache_expiration=1)
    obj_id = id(mongo)

    mongo = detector.get_service_instance("mongo", cache_expiration=1)
    assert id(mongo) == obj_id

    time.sleep(2)

    mongo = detector.get_service_instance("mongo", cache_expiration=1)
    assert id(mongo) != obj_id

    # Close connection...
    mongo.disconnect()

    # test connection... and should fail
    # ???

    # ... close connection again ... nothing should happens
    mongo.disconnect()
