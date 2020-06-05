import pytz
import pytest
from datetime import datetime
from restapi.services.detect import detector
from restapi.tests import BaseTests
from restapi.tests import API_URI
from neobolt.exceptions import CypherSyntaxError
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log

if not detector.check_availability('neo4j'):
    log.warning("Skipping neo4j test: service not avaliable")
else:
    class TestNeo4j(BaseTests):

        @staticmethod
        def test_endpoint(client):
            r = client.get(f"{API_URI}/tests/neo4j/1")
            assert r.status_code == 200

            r = client.get(f"{API_URI}/tests/neo4j/2")
            assert r.status_code == 400

        @staticmethod
        def test_connector(fake):

            try:
                detector.get_service_instance(
                    "neo4j",
                    host="invalidhostname",
                    port=123
                )
                pytest.fail("No exception raised on unavailable service")
            except ServiceUnavailable:
                pass

            neo4j = detector.get_service_instance("neo4j")
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

            assert neo4j.createUniqueIndex('a', 'b') == 'a#_#b'

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
