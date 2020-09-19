import time
from datetime import datetime

import dateutil.parser
import pytest
import pytz
from neo4j.exceptions import CypherSyntaxError

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.tests import API_URI, BaseTests
from restapi.utilities.logs import log

CONNECTOR = "neo4j"

if not detector.check_availability(CONNECTOR):

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is None

    try:
        obj = detector.get_service_instance(CONNECTOR)
        pytest("No exception raised")
    except ServiceUnavailable:
        pass

    log.warning("Skipping {} tests: service not available", CONNECTOR)
else:

    log.info("Executing {} tests", CONNECTOR)

    class TestNeo4j(BaseTests):
        def test_endpoint(self, client):
            r = client.get(f"{API_URI}/tests/neo4j/1")
            assert r.status_code == 200

            r = client.get(f"{API_URI}/tests/neo4j/2")
            assert r.status_code == 400

            r = client.get(f"{API_URI}/tests/neo4j/3")
            assert r.status_code == 200
            data = self.get_content(r)
            data["created"] = dateutil.parser.parse(data["created"])
            data["modified1"] = dateutil.parser.parse(data["modified1"])
            data["modified2"] = dateutil.parser.parse(data["modified2"])
            assert data["created"] < data["modified1"]
            assert data["modified1"] < data["modified2"]

        @staticmethod
        def test_connector(app, fake):

            # Run this before the init_services,
            # get_debug_instance is able to load what is needed
            obj = detector.get_debug_instance(CONNECTOR)
            assert obj is not None

            detector.init_services(
                app=app,
                project_init=False,
                project_clean=False,
            )

            try:
                detector.get_service_instance(
                    CONNECTOR, host="invalidhostname", port=123
                )
                pytest.fail("No exception raised on unavailable service")
            except ServiceUnavailable:
                pass

            try:
                detector.get_service_instance(
                    CONNECTOR,
                    user="invaliduser",
                )
                pytest.fail("No exception raised on unavailable service")
            except ServiceUnavailable:
                pass

            obj = detector.get_service_instance(CONNECTOR)
            assert obj is not None

            for row in obj.cypher("MATCH (u: User) RETURN u limit 1"):
                u = obj.User.inflate(row[0])
                assert u.email is not None
                break

            v = fake.random_letters(24)
            # Create a fake token and verify that is linked to nobody
            t = obj.Token(jti=v, token=v, creation=datetime.now(pytz.utc)).save()
            assert t.emitted_for.single() is None
            t.delete()

            try:
                obj.cypher("MATCH (n) RETURN n with a syntax error")
            # Query informtaion are removed from the CypherSyntaxError exception
            except CypherSyntaxError as e:
                assert str(e) == "{code: None} {message: None}"

            assert obj.sanitize_input("x") == "x"
            assert obj.sanitize_input("x ") == "x"
            assert obj.sanitize_input(" x") == "x"
            assert obj.sanitize_input("*x") == "x"
            assert obj.sanitize_input("x*") == "x"
            assert obj.sanitize_input("x~") == "x"
            assert obj.sanitize_input("~x") == "x"
            assert obj.sanitize_input("x'") == "x\\'"
            assert obj.sanitize_input("   *~~**x~~**  ") == "x"
            assert obj.sanitize_input(" x x ") == "x x"

            assert obj.fuzzy_tokenize('"x y"') == '"x y"'
            assert obj.fuzzy_tokenize("x AND y") == "x~1 AND y~1"
            assert obj.fuzzy_tokenize("x + y") == "x~1 + y~1"
            assert obj.fuzzy_tokenize("AND OR + NOT !") == "AND OR + NOT !"

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
