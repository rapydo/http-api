import json

from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_inputs(self, client: FlaskClient) -> None:

        # This test verifies that buildData is always able to randomly create
        # valid inputs for endpoints with inputs defined by marshamallow schemas
        schema = self.getDynamicInputSchema(client, "tests/inputs", {})
        # Expected number of fields
        assert len(schema) == 13
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
        assert len(field) == 7  # 5 mandatory fields + min + max
        assert field["key"] == "MYDATE"
        assert field["type"] == "date"
        # Here the key is not lower cased and the label is not explicitly set
        # So the label will exactly match the key (without additiona of .title)
        assert field["label"] == field["key"]
        assert field["label"] != field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "min" in field
        assert "max" in field

        field = schema[2]
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

        field = schema[3]
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

        field = schema[4]
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

        field = schema[5]
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

        field = schema[6]
        assert len(field) == 6  # 5 mandatory fields + max
        assert field["key"] == "mymaxstr"
        assert field["type"] == "string"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "min" not in field
        assert "max" in field
        assert field["max"] == 7

        field = schema[7]
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

        field = schema[8]
        assert len(field) == 6  # 5 mandatory fields + schema
        assert field["key"] == "mynested"
        assert field["type"] == "nested"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "schema" in field

        field = schema[9]
        assert len(field) == 6  # 5 mandatory fields + schema
        assert field["key"] == "mynullablenested"
        assert field["type"] == "nested"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "schema" in field

        field = schema[10]
        assert len(field) == 5  # 5 mandatory fields
        assert field["key"] == "mylist"
        assert field["type"] == "string[]"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]

        field = schema[11]
        assert len(field) == 5  # 5 mandatory fields
        assert field["key"] == "mylist2"
        # The list is defined as List(CustomInt) and CustomInt is resolved as int
        assert field["type"] == "int[]"
        assert field["label"] == field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]

        field = schema[12]
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
        data["mylist3"] = json.dumps(["mycustominputvalue"])

        r = client.post(f"{API_URI}/tests/inputs", data=data)
        assert r.status_code == 204

        # This is to verify that access_token, if provided is excluded from parameters
        # And do not raise any ValidationError for unknown input
        _, token = self.do_login(client, None, None)
        data["access_token"] = token
        r = client.post(f"{API_URI}/tests/inputs", data=data)
        assert r.status_code == 204

        # This is to verify that unknown inputs raise a ValidationError
        data["unknown"] = "input"
        r = client.post(f"{API_URI}/tests/inputs", data=data)
        assert r.status_code == 400
