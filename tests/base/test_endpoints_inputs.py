import orjson
import pytest

from restapi.connectors import Connector
from restapi.env import Env
from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_inputs(self, client: FlaskClient) -> None:
        # This test verifies that buildData is always able to randomly create
        # valid inputs for endpoints with inputs defined by marshamallow schemas
        schema = self.get_dynamic_input_schema(client, "tests/inputs", {})
        # Expected number of fields
        assert len(schema) == 14
        for field in schema:
            # Always in the schema
            assert "key" in field
            assert "type" in field
            assert "label" in field
            assert "description" in field
            assert "required" in field

            # Other optional keys
            # - default
            # - min
            # - max
            # - options
            # - schema in case of nested fields

        field = schema[0]
        assert len(field) == 6  # 5 mandatory fields + min
        assert field["key"] == "mystr"
        assert field["type"] == "string"
        # This is the default case: both label and description are not explicitly set
        # if key is lower-cased the corrisponding label will be titled
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "min" in field
        assert field["min"] == 4
        assert "max" not in field

        field = schema[1]
        assert len(field) == 5  # 5 mandatory fields, min and max not set
        assert field["key"] == "MYDATE"
        assert field["type"] == "date"
        # Here the key is not lower cased and the label is not explicitly set
        # So the label will exactly match the key (without additiona of .title)
        assert field["label"] == field["key"]
        assert field["label"] != field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]

        field = schema[2]
        assert len(field) == 7  # 5 mandatory fields + min + max
        assert field["key"] == "MYDATETIME"
        assert field["type"] == "datetime"
        # Here the key is not lower cased and the label is not explicitly set
        # So the label will exactly match the key (without additiona of .title)
        assert field["label"] == field["key"]
        assert field["label"] != field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "min" in field
        assert "max" in field

        field = schema[3]
        assert len(field) == 7  # 5 mandatory fields + min + max
        assert field["key"] == "myint_exclusive"
        assert field["type"] == "int"
        # Here an explicit label is defined but not a description, so is == to the label
        assert field["label"] != field["key"]
        assert field["label"] != field["key"].title()
        assert field["label"] == "Int exclusive field"
        assert field["description"] == field["label"]
        assert field["required"]
        assert "min" in field
        assert field["min"] == 2
        assert "max" in field
        assert field["max"] == 9

        field = schema[4]
        assert len(field) == 7  # 5 mandatory fields + min + max
        assert field["key"] == "myint_inclusive"
        assert field["type"] == "int"
        # Here both label and description are explicitly set
        assert field["label"] != field["key"]
        assert field["label"] != field["key"].title()
        assert field["label"] == "Int inclusive field"
        assert field["description"] != field["label"]
        assert field["description"] == "This field accepts values in a defined range"
        assert field["required"]
        assert "min" in field
        assert field["min"] == 1
        assert "max" in field
        assert field["max"] == 10

        field = schema[5]
        assert len(field) == 6  # 5 mandatory fields + options
        assert field["key"] == "myselect"
        assert field["type"] == "string"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "options" in field
        assert isinstance(field["options"], dict)
        assert len(field["options"]) == 2
        assert "a" in field["options"]
        assert "b" in field["options"]
        # The field defines labels and keys for all options
        assert field["options"]["a"] == "A"
        assert field["options"]["b"] == "B"

        field = schema[6]
        assert len(field) == 6  # 5 mandatory fields + options
        assert field["key"] == "myselect2"
        assert field["type"] == "string"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "options" in field
        assert isinstance(field["options"], dict)
        assert len(field["options"]) == 2
        assert "a" in field["options"]
        assert "b" in field["options"]
        # The field wrongly defines labels, so are defaulted to keys
        assert field["options"]["a"] == "a"
        assert field["options"]["b"] == "b"

        field = schema[7]
        assert len(field) == 6  # 5 mandatory fields + max
        assert field["key"] == "mymaxstr"
        assert field["type"] == "string"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "min" not in field
        assert "max" in field
        assert field["max"] == 7

        field = schema[8]
        assert len(field) == 7  # 5 mandatory fields + min + max
        assert field["key"] == "myequalstr"
        assert field["type"] == "string"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "min" in field
        assert "max" in field
        assert field["min"] == 6
        assert field["max"] == 6

        field = schema[9]
        assert len(field) == 6  # 5 mandatory fields + schema
        assert field["key"] == "mynested"
        assert field["type"] == "nested"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "schema" in field

        field = schema[10]
        assert len(field) == 6  # 5 mandatory fields + schema
        assert field["key"] == "mynullablenested"
        assert field["type"] == "nested"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "schema" in field

        field = schema[11]
        assert len(field) == 5  # 5 mandatory fields
        assert field["key"] == "mylist"
        assert field["type"] == "string[]"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]

        field = schema[12]
        assert len(field) == 5  # 5 mandatory fields
        assert field["key"] == "mylist2"
        # The list is defined as List(CustomInt) and CustomInt is resolved as int
        assert field["type"] == "int[]"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]

        field = schema[13]
        assert len(field) == 5  # 5 mandatory fields
        assert field["key"] == "mylist3"
        # The type is key[] ... should be something more explicative like FieldName[]
        # assert field["type"] == "CustomGenericField[]"
        assert field["type"] == "mylist3[]"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]

        data = self.buildData(schema)

        # mylist3 is a list of custom field, buildData can't automatically set a value
        assert "mylist3" not in data
        data["mylist3"] = orjson.dumps(["mycustominputvalue"]).decode("UTF8")

        r = client.post(f"{API_URI}/tests/inputs", json=data)
        assert r.status_code == 204

        # This is to verify that access_token, if provided is excluded from parameters
        # And do not raise any ValidationError for unknown input

        if Env.get_bool("AUTH_ENABLE"):
            _, token = self.do_login(client, None, None)
            data["access_token"] = token
            r = client.post(f"{API_URI}/tests/inputs", json=data)
            assert r.status_code == 204

        # This is to verify that unknown inputs raise a ValidationError
        data["unknown"] = "input"
        r = client.post(f"{API_URI}/tests/inputs", json=data)
        assert r.status_code == 400

    @pytest.mark.skipif(
        not Connector.check_availability("neo4j"),
        reason="This test needs neo4j to be available",
    )
    def test_neo4j_inputs(self, client: FlaskClient) -> None:
        headers, _ = self.do_login(client, None, None)
        schema = self.get_dynamic_input_schema(client, "tests/neo4jinputs", headers)
        assert len(schema) == 1

        field = schema[0]
        assert field["key"] == "choice"
        # This is because the Neo4jChoice field is not completed for deserialization
        # It is should be automatically translated into a select, with options by
        # including a validation OneOf
        assert "options" not in field

        r = client.post(
            f"{API_URI}/tests/neo4jinputs", json={"choice": "A"}, headers=headers
        )
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, dict)
        assert "choice" in response
        assert "key" in response["choice"]
        assert "description" in response["choice"]
        assert response["choice"]["key"] == "A"
        assert response["choice"]["description"] == "AAA"

        assert "relationship_count" in response
        assert isinstance(response["relationship_count"], int)
        assert response["relationship_count"] > 0

        assert "relationship_single" in response
        assert isinstance(response["relationship_single"], dict)
        assert "uuid" in response["relationship_single"]

        assert "relationship_many" in response
        assert isinstance(response["relationship_many"], list)
        assert len(response["relationship_many"]) > 0
        assert isinstance(response["relationship_many"][0], dict)
        assert "token_type" in response["relationship_many"][0]

        r = client.post(
            f"{API_URI}/tests/neo4jinputs", json={"choice": "B"}, headers=headers
        )
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, dict)
        assert "choice" in response
        assert "key" in response["choice"]
        assert "description" in response["choice"]
        assert response["choice"]["key"] == "B"
        assert response["choice"]["description"] == "BBB"

        r = client.post(
            f"{API_URI}/tests/neo4jinputs", json={"choice": "C"}, headers=headers
        )
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, dict)
        assert "choice" in response
        assert "key" in response["choice"]
        assert "description" in response["choice"]
        assert response["choice"]["key"] == "C"
        assert response["choice"]["description"] == "CCC"

        r = client.post(
            f"{API_URI}/tests/neo4jinputs", json={"choice": "D"}, headers=headers
        )
        # This should fail, but Neo4jChoice are not validated as input
        # assert r.status_code == 400
        # Since validation is not implemented, D is accepted But since it is
        # not included in the choice, the description will simply match the key
        assert r.status_code == 200
        response = self.get_content(r)
        assert isinstance(response, dict)
        assert "choice" in response
        assert "key" in response["choice"]
        assert "description" in response["choice"]
        assert response["choice"]["key"] == "D"
        assert response["choice"]["description"] == "D"
