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
from restapi.connectors.neo4j.parser import DataDump, NodeDump, RelationDump
from restapi.exceptions import ServiceUnavailable
from restapi.services.authentication import BaseAuthentication
from restapi.tests import API_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log

CONNECTOR = "neo4j"

if not Connector.check_availability(CONNECTOR):

    try:
        obj = connector.get_instance()
        pytest.fail("No exception raised")  # pragma: no cover
    except ServiceUnavailable:
        pass

    log.warning("Skipping {} tests: service not available", CONNECTOR)
else:

    log.info("Executing {} tests", CONNECTOR)

    class TestNeo4j(BaseTests):
        def test_endpoint(self, client: FlaskClient) -> None:
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
        def test_connector(app: Flask, faker: Faker) -> None:

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

            try:
                obj.InvalidModel
                pytest.fail("No exception raised on InvalidModel")  # pragma: no cover
            except AttributeError as e:
                assert str(e) == "Model InvalidModel not found"

            for row in obj.cypher("MATCH (u: User) RETURN u limit 1"):
                u = obj.User.inflate(row[0])
                assert u.email is not None
                break

            v = faker.random_letters(24)
            # Create a fake token and verify that is linked to nobody
            t = obj.Token(
                jti=v,
                token=v,
                token_type=BaseAuthentication.FULL_TOKEN,
                creation=datetime.now(pytz.utc),
            ).save()
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

        @staticmethod
        def test_parser() -> None:

            try:
                # missing :type
                node1 = NodeDump("TestNode1", fields=["f1"])
                pytest.fail("No exception raised")  # pragma: no cover
            except ValueError:
                pass

            node1 = NodeDump("TestNode1", fields=["f1:string", "f2:int", "f3:float"])

            node2 = NodeDump("TestNode2", fields=["f1:string", "f2:int", "f3:float"])

            rel = RelationDump(
                "TestNode1",
                "MY_REL",
                "TestNode2",
                fields=["f1", "f1", "custom:string"],
            )

            # To be verified the correct type assignment
            node1.dump("test-string", 10, 20.30)
            # This is a duplicate, should be ignored
            node1.dump("test-string", 10, 20.30)
            node1.dump("test-string-bis", 11, 22.33)
            node2.dump("test-string2", 12, 24.36)

            rel.dump("test-string", "test-string2", "custom")
            rel.dump("test-string-bis", "test-string2", "custom")

            try:
                node1.dump("only-one")
                pytest.fail("No exception raised")  # pragma: no cover
            except ValueError:
                pass

            try:
                node1.dump("only-two", 2)
                pytest.fail("No exception raised")  # pragma: no cover
            except ValueError:
                pass

            try:
                node1.dump("too-many", 2, 2.2, 2.22)
                pytest.fail("No exception raised")  # pragma: no cover
            except ValueError:
                pass

            try:
                rel.dump("test-string", "test-string2")
                pytest.fail("No exception raised")  # pragma: no cover
            except ValueError:
                pass

            try:
                rel.dump("test-string", "test-string2", "custom1", "custom2")
                pytest.fail("No exception raised")  # pragma: no cover
            except ValueError:
                pass

            # test the errors if a wrong number of fields is given

            # What happens with a dump of wrong keys?
            # Nothing, but will be ignored and nothing will be created...
            rel.dump("does-not-exist", "test-string2", "custom")

            node1.store()
            node2.store()
            rel.store()

            obj = connector.get_instance()

            data = obj.cypher("MATCH (n: TestNode1) RETURN n")
            assert isinstance(data[0][0]["f1"], str)
            assert isinstance(data[0][0]["f2"], int)
            assert isinstance(data[0][0]["f3"], float)
            assert len(data) == 2
            f1 = data[0][0]["f1"]
            f2 = data[0][0]["f2"]
            f3 = data[0][0]["f3"]
            assert f1 == "test-string" or f1 == "test-string-bis"
            assert f2 == 10 or f2 == 11
            assert f3 == 20.30 or f3 == 22.33
            f1 = data[1][0]["f1"]
            f2 = data[1][0]["f2"]
            f3 = data[1][0]["f3"]
            assert f1 == "test-string" or f1 == "test-string-bis"
            assert f2 == 10 or f2 == 11
            assert f3 == 20.30 or f3 == 22.33

            data = obj.cypher("MATCH (n: TestNode2) RETURN n")
            assert len(data) == 1

            data = obj.cypher("MATCH (n)-[r:MY_REL]->(m) RETURN r")
            assert len(data) == 2
            assert data[0][0]["custom"] == "custom"

            DataDump.switch_label("TestNode2", "TestNode3")

            data = obj.cypher("MATCH (n: TestNode2) RETURN n")
            assert len(data) == 0

            data = obj.cypher("MATCH (n: TestNode3) RETURN n")
            assert len(data) == 1

            DataDump.delete_relationships("TestNode1", "MY_REL", "TestNode3", limit=1)

            data = obj.cypher("MATCH (n)-[r:MY_REL]->(m) RETURN r")
            assert len(data) == 0

            data = obj.cypher("MATCH (n: TestNode1) RETURN n")
            assert len(data) == 2

            DataDump.delete_nodes("TestNode1", limit=1)
            data = obj.cypher("MATCH (n: TestNode1) RETURN n")
            assert len(data) == 0

            DataDump.delete_nodes("TestNode3")
            data = obj.cypher("MATCH (n: TestNode3) RETURN n")
            assert len(data) == 0

            # TestNode2 does not exist... no errors should be raised
            DataDump.switch_label("TestNode2", "TestNode3")

            # Test DETACH DELETE

            node1 = NodeDump("T1", fields=["f1:string"])
            node2 = NodeDump("T2", fields=["f1:string"])
            rel = RelationDump("T1", "R1", "T2", fields=["f1", "f1"])

            node1.dump("a")
            node2.dump("b")
            rel.dump("a", "b")

            node1.store()
            node2.store()
            rel.store()

            data = obj.cypher("MATCH (n: T1) RETURN n")
            assert len(data) == 1
            data = obj.cypher("MATCH (n: T2) RETURN n")
            assert len(data) == 1
            data = obj.cypher("MATCH (n)-[r:R1]->(m) RETURN r")
            assert len(data) == 1

            # Due to detach delete this will delete both T1 and R1
            # Of course T2 will not be deleted
            DataDump.delete_nodes("T1")

            data = obj.cypher("MATCH (n: T1) RETURN n")
            assert len(data) == 0
            data = obj.cypher("MATCH (n: T2) RETURN n")
            assert len(data) == 1
            data = obj.cypher("MATCH (n)-[r:R1]->(m) RETURN r")
            assert len(data) == 0

            DataDump.delete_nodes("T2")
            data = obj.cypher("MATCH (n: T2) RETURN n")
            assert len(data) == 0

            assert node1.count == 1
            assert node1.filepath.exists()
            node1.flush_cache()
            assert node1.count == 0
            assert node1.filepath.exists()

            node1.dump("a")
            assert node1.count == 1
            node1.clean()
            assert node1.count == 0
            assert not node1.filepath.exists()
