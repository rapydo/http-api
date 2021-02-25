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
            assert "key" in field
            assert "type" in field
            assert "label" in field
            assert "description" in field
            assert "required" in field
            # This will fail in case of select and validations...
            # it is just to stop the tests and improve this part
            assert len(field) == 5

        field = schema[0]
        assert field["key"] == "mystr"
        assert field["type"] == "string"
        # This is the default case: both label and description are not explicitly set
        # if key is lower-cased the corrisponding label will be titled
        assert field["label"] == field["type"].title()
        assert field["description"] == field["label"]
        assert field["required"]

        field = schema[1]
        assert field["key"] == "MYDATE"
        assert field["type"] == "date"
        # Here the key is not lower cased and the label is not explicitly set
        # So the label will exactly match the key (without additiona of .title)
        assert field["label"] == field["type"]
        assert field["label"] != field["type"].title()
        assert field["description"] == field["label"]
        assert field["required"]

        field = schema[2]
        assert field["key"] == "myint_exclusive"
        assert field["type"] == "int"
        # Here an explicit label is defined but not a description, so is == to the label
        assert field["label"] != field["type"]
        assert field["label"] != field["type"].title()
        assert field["label"] == "Int exclusive field"
        assert field["description"] == field["label"]
        assert field["required"]

        field = schema[3]
        assert field["key"] == "myint_inclusive"
        assert field["type"] == "int"
        # Here both label and description are explicitly set
        assert field["label"] != field["type"]
        assert field["label"] != field["type"].title()
        assert field["label"] == "Int inclusive field"
        assert field["description"] != field["label"]
        assert (
            field["description"]
            == "This field will accept values amongo a defined range"
        )
        assert field["required"]

        data = self.buildData(schema)

        r = client.post(f"{API_URI}/tests/inputs", data=data)
        assert r.status_code == 204
