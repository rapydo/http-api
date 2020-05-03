# -*- coding: utf-8 -*-

from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_neo4j():

    if not detector.check_availability('neo4j'):
        log.warning("Skipping neo4j test: service not avaiable")
        return False

    neo4j = detector.connectors_instances.get('neo4j').get_instance()
    for u in neo4j.cypher("MATCH (u: User) RETURN u limit 1"):
        u.inflate(neo4j.User)
        assert u.email is not None
        break

    assert neo4j.createUniqueIndex('a', 'b') == 'a#_#b'

    assert neo4j.sanitize_input("x") == "x"
    assert neo4j.sanitize_input("x ") == "x"
    assert neo4j.sanitize_input(" x") == "x"
    assert neo4j.sanitize_input("*x") == "x"
    assert neo4j.sanitize_input("x*") == "x"
    assert neo4j.sanitize_input("x~") == "x"
    assert neo4j.sanitize_input("~x") == "x"
    assert neo4j.sanitize_input("x'") == "x\\'"
    assert neo4j.sanitize_input("   *~ ~** x  ~~**  ") == "x"

    assert neo4j.fuzzy_tokenize("x AND y") == "x~1 AND y~1"
