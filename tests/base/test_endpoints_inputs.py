from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_inputs(self, client: FlaskClient) -> None:

        # This test verifies that buildData is always able to randomly create
        # valid inputs for endpoints with inputs defined by marshamallow schemas
        schema = self.getDynamicInputSchema(client, "tests/inputs", {})
        # Expected number of fields
        NUM_FIELDS = 4
        assert len(schema) == NUM_FIELDS
        for field in schema:

            # Always in the schema
            assert "key" in field
            assert "type" in field
            assert "label" in field
            assert "description" in field
            assert "required" in field

            # Other optional keys
            # - default
            # - multiple: True|False
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
        assert field["min"] == 1
        assert "max" not in field

        field = schema[1]
        assert len(field) == 5  # 5 mandatory fields
        assert field["key"] == "MYDATE"
        assert field["type"] == "date"
        # Here the key is not lower cased and the label is not explicitly set
        # So the label will exactly match the key (without additiona of .title)
        assert field["label"] == field["key"]
        assert field["label"] != field["key"].title()
        assert field["description"] == field["label"]
        assert field["required"]
        assert "min" not in field
        assert "max" not in field

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

        data = self.buildData(schema)

        r = client.post(f"{API_URI}/tests/inputs", data=data)
        assert r.status_code == 204
