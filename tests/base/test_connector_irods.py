import os
import pytest
from restapi.services.detect import detector
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log


def test_irods(app):

    if not detector.check_availability('irods'):
        log.warning("Skipping irods test: service not available")
        return False

    detector.init_services(
        app=app,
        project_init=False,
        project_clean=False,
    )

    try:
        detector.get_service_instance(
            "irods",
            host="invalidhostname",
            port=123
        )
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    irods = detector.get_service_instance("irods")
    assert irods is not None

    home = irods.get_user_home()

    assert irods.get_user_home("xxyyzz") == "/tempZone/home/xxyyzz"
    assert home == "/tempZone/home/irods"

    path = irods.get_absolute_path("tempZone", "home", "irods")
    assert path == home

    # DEFINING SOME PATHS
    data_obj = os.path.join(path, "test.txt")
    collection = os.path.join(path, "sub")
    # collection2 = os.path.join(path, "sub2")
    data_obj2 = os.path.join(collection, "test2.txt")
    data_obj3 = os.path.join(collection, "test3.txt")

    # BASIC TESTS ON EXISTANCE
    assert irods.get_collection_from_path(data_obj) == path

    assert irods.exists(path)
    assert not irods.exists(data_obj)

    assert irods.is_collection(path)
    assert not irods.is_collection(data_obj)

    assert not irods.is_dataobject(path)
    assert not irods.is_dataobject(data_obj)

    # CREATE FIRST COLLECTION AND FIRST FILE
    irods.create_empty(collection, directory=True)
    irods.create_empty(data_obj)

    assert irods.exists(collection)
    assert irods.exists(data_obj)

    assert irods.is_collection(collection)
    assert not irods.is_collection(data_obj)

    assert not irods.is_dataobject(collection)
    assert irods.is_dataobject(data_obj)

    content = irods.list(path)
    # here we should find only collection and data_obj
    assert len(content) == 2
    assert "sub" in content
    assert "test.txt" in content
    assert "objects" in content["sub"]

    # COPY AND MOVE
    irods.copy(data_obj, data_obj2)
    irods.move(data_obj2, data_obj3)
    # irods.copy(collection, collection2, recursive=True)

    content = irods.list(path, recursive=True)
    # here we should also find data_obj3
    assert len(content) == 2
    assert "sub" in content
    assert "test.txt" in content
    assert "objects" in content["sub"]
    assert "test3.txt" in content["sub"]["objects"]
    # If not recursive, we should not find content of collections
    content = irods.list(path)
    assert "test3.txt" not in content["sub"]["objects"]

    irods.remove(data_obj3)
    content = irods.list(path, recursive=True)
    # here we should no longer find data_obj3
    assert len(content) == 2
    assert "sub" in content
    assert "test.txt" in content
    assert "objects" in content["sub"]
    assert "test3.txt" not in content["sub"]["objects"]

    # irods.remove(collection2, recursive=True)
    # content = irods.list(path)
    # here we should also find collection2
    # assert content == {}
