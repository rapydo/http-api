import time
from datetime import datetime

import dateutil.parser
import pytest
import pytz
from faker import Faker
from flask import Flask
from neo4j.exceptions import CypherSyntaxError

from restapi.connectors import Connector
from restapi.connectors import neo4j as connector
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.tests import API_URI, BaseTests
from restapi.utilities.logs import log

CONNECTOR = "neo4j"

if not Connector.check_availability(CONNECTOR):

    try:
        obj = connector.get_instance()
        pytest.fail("No exception raised")  # pragma: no cover
    except ServiceUnavailable:
        pass

    log.warning("Skipping {} tests: service not available", CONNECTOR)
# Alwas enabled during core tests
elif not Env.get_bool("TEST_CORE_ENABLED"):  # pragma: no cover
    log.warning("Skipping {} tests: only avaiable on core", CONNECTOR)
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
        def test_connector(app: Flask, fake: Faker) -> None:

            detector.init_services(
                app=app,
                project_init=False,
                project_clean=False,
            )

            try:
                connector.get_instance(host="invalidhostname", port=123)
                pytest.fail(
                    "No exception raised on unavailable service"
                )  # pragma: no cover
            except ServiceUnavailable:
                pass

            try:
                connector.get_instance(
                    user="invaliduser",
                )
                pytest.fail(
                    "No exception raised on unavailable service"
                )  # pragma: no cover
            except ServiceUnavailable:
                pass

            obj = connector.get_instance()
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

            obj.disconnect()

            # a second disconnect should not raise any error
            obj.disconnect()

            # Create new connector with short expiration time
            obj = connector.get_instance(expiration=2, verification=1)
            obj_id = id(obj)

            # Connector is expected to be still valid
            obj = connector.get_instance(expiration=2, verification=1)
            assert id(obj) == obj_id

            time.sleep(1)

            # The connection should have been checked and should be still valid
            obj = connector.get_instance(expiration=2, verification=1)
            assert id(obj) == obj_id

            time.sleep(1)

            # Connection should have been expired and a new connector been created
            obj = connector.get_instance(expiration=2, verification=1)
            assert id(obj) != obj_id

            assert obj.is_connected()
            obj.disconnect()
            assert not obj.is_connected()

            # ... close connection again ... nothing should happens
            obj.disconnect()

            with connector.get_instance() as obj:
                assert obj is not None
