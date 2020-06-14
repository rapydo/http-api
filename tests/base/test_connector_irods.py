import os
import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "irods"


def test_irods(app, faker):

    if not detector.check_availability(CONNECTOR):

        obj = detector.get_debug_instance(CONNECTOR)
        assert obj is None

        log.warning("Skipping irods test: service not available")
        return False

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    from irods import exception as iexceptions

    obj = detector.get_service_instance(CONNECTOR, authscheme="PAM")
    assert obj is not None

    try:
        obj = detector.get_service_instance(
            CONNECTOR, authscheme="PAM", password=faker.pystr()
        )

        pytest.fail("This should fail because password is wrong")
    except iexceptions.PAM_AUTH_PASSWORD_FAILED:
        pass

    try:
        obj = detector.get_service_instance(CONNECTOR, authscheme="GSI")
        pytest.fail("GSI should fail because no certificate is set by default")
    except ServiceUnavailable:
        pass

    obj = detector.get_service_instance(CONNECTOR, authscheme="XYZ")
    # since a password is provided by default authscheme is fallback to credentials
    assert obj is not None
    try:
        detector.get_service_instance(CONNECTOR, authscheme="XYZ", password=None)
        pytest.fail("This should fail because authscheme is invalid")
    except ServiceUnavailable:
        pass

    try:
        obj = detector.get_service_instance(CONNECTOR, password=faker.pystr())

        pytest.fail("This should fail because password is wrong")
    except iexceptions.CAT_INVALID_AUTHENTICATION:
        pass

    obj = detector.get_service_instance(CONNECTOR)
    assert obj is not None

    home = obj.get_user_home()

    assert obj.get_user_home("xxyyzz") == "/tempZone/home/xxyyzz"
    assert home == "/tempZone/home/obj"

    path = obj.get_absolute_path("tempZone", "home", "irods")
    assert path == home

    # DEFINING SOME PATHS
    data_obj = os.path.join(path, "test.txt")
    collection = os.path.join(path, "sub")
    # collection2 = os.path.join(path, "sub2")
    data_obj2 = os.path.join(collection, "test2.txt")
    data_obj3 = os.path.join(collection, "test3.txt")

    # BASIC TESTS ON EXISTANCE
    assert obj.get_collection_from_path(data_obj) == path

    assert obj.exists(path)
    assert not obj.exists(data_obj)

    assert obj.is_collection(path)
    assert not obj.is_collection(data_obj)

    assert not obj.is_dataobject(path)
    assert not obj.is_dataobject(data_obj)

    # CREATE FIRST COLLECTION AND FIRST FILE
    obj.create_empty(collection, directory=True)
    obj.create_empty(data_obj)

    assert obj.exists(collection)
    assert obj.exists(data_obj)

    assert obj.is_collection(collection)
    assert not obj.is_collection(data_obj)

    assert not obj.is_dataobject(collection)
    assert obj.is_dataobject(data_obj)

    content = obj.list(path)
    # here we should find only collection and data_obj
    assert len(content) == 2
    assert "sub" in content
    assert "test.txt" in content
    assert "objects" in content["sub"]

    # COPY AND MOVE
    obj.copy(data_obj, data_obj2)
    obj.move(data_obj2, data_obj3)
    # obj.copy(collection, collection2, recursive=True)

    content = obj.list(path, recursive=True)
    # here we should also find data_obj3
    assert len(content) == 2
    assert "sub" in content
    assert "test.txt" in content
    assert "objects" in content["sub"]
    assert "test3.txt" in content["sub"]["objects"]
    # If not recursive, we should not find content of collections
    content = obj.list(path)
    assert "test3.txt" not in content["sub"]["objects"]

    obj.remove(data_obj3)
    content = obj.list(path, recursive=True)
    # here we should no longer find data_obj3
    assert len(content) == 2
    assert "sub" in content
    assert "test.txt" in content
    assert "objects" in content["sub"]
    assert "test3.txt" not in content["sub"]["objects"]

    # obj.remove(collection2, recursive=True)
    # content = obj.list(path)
    # here we should also find collection2
    # assert content == {}

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    obj_id = id(obj)

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    assert id(obj) == obj_id

    time.sleep(1)

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    assert id(obj) != obj_id

    # Close connection...
    obj.disconnect()

    # Test connection... should fail!
    # ??

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with detector.get_service_instance(CONNECTOR) as obj:
        assert obj is not None

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_debug_instance("invalid")
    assert obj is None
