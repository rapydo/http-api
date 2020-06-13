import time
from datetime import datetime

import dateutil.parser
import pytest
import pytz
from neobolt.exceptions import CypherSyntaxError

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.tests import API_URI, BaseTests
from restapi.utilities.logs import log

if not detector.check_availability("neo4j"):
    log.warning("Skipping neo4j test: service not avaliable")
else:

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
            assert (data["modified1"] - data["created"]).microseconds < 120
            assert (data["modified2"] - data["created"]).microseconds > 120
            assert data["modified1"] < data["modified2"]
            assert (data["modified2"] - data["modified1"]).microseconds > 120

        @staticmethod
        def test_connector(app, fake):

            detector.init_services(
                app=app, project_init=False, project_clean=False,
            )

            try:
                detector.get_service_instance("neo4j", host="invalidhostname", port=123)
                pytest.fail("No exception raised on unavailable service")
            except ServiceUnavailable:
                pass

            try:
                detector.get_service_instance(
                    "neo4j", user="invaliduser",
                )
                pytest.fail("No exception raised on unavailable service")
            except ServiceUnavailable:
                pass

            neo4j = detector.get_service_instance("neo4j")
            assert neo4j is not None

            for row in neo4j.cypher("MATCH (u: User) RETURN u limit 1"):
                u = neo4j.User.inflate(row[0])
                assert u.email is not None
                break

            v = fake.random_letters(24)
            # Create a fake token and verify that is linked to nobody
            t = neo4j.Token(jti=v, token=v, creation=datetime.now(pytz.utc)).save()
            assert neo4j.getSingleLinkedNode(t.emitted_for) is None
            t.delete()

            try:
                neo4j.cypher("MATCH (n) RETURN n with a syntax error")
            # Query informtaion are removed from the CypherSyntaxError exception
            except CypherSyntaxError as e:
                assert str(e) == "Failed to execute Cypher Query"

            assert neo4j.createUniqueIndex("a", "b") == "a#_#b"

            assert neo4j.sanitize_input("x") == "x"
            assert neo4j.sanitize_input("x ") == "x"
            assert neo4j.sanitize_input(" x") == "x"
            assert neo4j.sanitize_input("*x") == "x"
            assert neo4j.sanitize_input("x*") == "x"
            assert neo4j.sanitize_input("x~") == "x"
            assert neo4j.sanitize_input("~x") == "x"
            assert neo4j.sanitize_input("x'") == "x\\'"
            assert neo4j.sanitize_input("   *~~**x~~**  ") == "x"
            assert neo4j.sanitize_input(" x x ") == "x x"

            assert neo4j.fuzzy_tokenize('"x y"') == '"x y"'
            assert neo4j.fuzzy_tokenize("x AND y") == "x~1 AND y~1"
            assert neo4j.fuzzy_tokenize("x + y") == "x~1 + y~1"
            assert neo4j.fuzzy_tokenize("AND OR + NOT !") == "AND OR + NOT !"

            neo4j = detector.get_service_instance("neo4j", cache_expiration=1)
            obj_id = id(neo4j)

            neo4j = detector.get_service_instance("neo4j", cache_expiration=1)
            assert id(neo4j) == obj_id

            time.sleep(1)

            neo4j = detector.get_service_instance("neo4j", cache_expiration=1)
            assert id(neo4j) != obj_id

            # Close connection...
            neo4j.disconnect()

            # Test connection... should fail!
            # ??

            # ... close connection again ... nothing should happens
            neo4j.disconnect()
