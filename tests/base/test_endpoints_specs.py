from restapi.tests import API_URI, BaseTests, FlaskClient

# from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_GET_specs(self, client: FlaskClient) -> None:

        r = client.get(f"{API_URI}/specs")
        assert r.status_code == 200
        content = self.get_content(r)
        assert "host" in content
        assert "info" in content
        assert "swagger" in content
        assert "schemes" in content
        assert "paths" in content
        assert "definitions" in content
        assert "/api/admin/users" not in content["paths"]

        # Not available in new spec... to be introduced?
        assert "basePath" not in content
        assert "consumes" not in content
        assert "produces" not in content
        # assert "application/json" in content["consumes"]
        # assert "application/json" in content["produces"]
        assert "tags" in content
        # This is no longer in root definition
        # Now it is set for each endpoint, when required
        assert "security" not in content
        # assert "Bearer" in content["security"][0]
        assert "securityDefinitions" in content
        assert "Bearer" in content["securityDefinitions"]

        headers, _ = self.do_login(client, None, None)
        r = client.get(f"{API_URI}/specs", headers=headers)
        assert r.status_code == 200
        content = self.get_content(r)
        assert "host" in content
        assert "info" in content
        assert "swagger" in content
        assert "schemes" in content
        assert "paths" in content
        assert "definitions" in content
        assert "/auth/logout" in content["paths"]

        # Not available in new spec... to be introduced?
        assert "basePath" not in content
        assert "consumes" not in content
        assert "produces" not in content
        # assert "application/json" in content["consumes"]
        # assert "application/json" in content["produces"]
        assert "tags" in content
        # This is no longer in root definition
        # Now it is set for each endpoint, when required
        assert "security" not in content
        # assert "Bearer" in content["security"][0]
        assert "securityDefinitions" in content
        assert "Bearer" in content["securityDefinitions"]

        # Based on the definition of InputSchema in test_inputs.py
        assert "/api/tests/inputs" in content["paths"]
        assert "post" in content["paths"]["/api/tests/inputs"]
        endpoint = content["paths"]["/api/tests/inputs"]["post"]
        assert "parameters" in endpoint
        assert "schema" in endpoint["parameters"]
        assert "$ref" in endpoint["parameters"]["schema"]
        assert endpoint["parameters"]["schema"]["$ref"] == "#/definitions/Input"

        assert "Input" in content["definitions"]

        schema = content["definitions"]["Input"]
        assert "properties" in schema
        assert "required" in schema
        assert "type" in schema
        assert schema["type"] == "object"

        assert "MYDATE" in schema["required"]
        assert "myequalstr" in schema["required"]
        assert "myint_exclusive" in schema["required"]
        assert "myint_inclusive" in schema["required"]
        assert "mylist" in schema["required"]
        assert "mylist2" in schema["required"]
        assert "mylist3" in schema["required"]
        assert "mymaxstr" in schema["required"]
        assert "mynested" in schema["required"]
        assert "myselect" in schema["required"]
        assert "myselect2" in schema["required"]
        assert "mystr" in schema["required"]

        properties = schema["propertiess"]
        f = "MYDATE"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "string"
        assert "format" in properties[f]
        assert properties[f]["format"] == "date-time"
        assert "x-minimum" in properties[f]
        assert "x-maximum" in properties[f]

        f = "myequalstr"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "string"
        assert "minLength" in properties[f]
        assert properties[f]["minLength"] == 6
        assert "maxLength" in properties[f]
        assert properties[f]["maxLength"] == 6

        f = "myint_exclusive"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "integer"
        assert "minimum" in properties[f]
        assert properties[f]["minimum"] == 1  # should be 2???
        assert "maximum" in properties[f]
        assert properties[f]["maximum"] == 10  # should be 9???

        f = "myint_inclusive"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "integer"
        assert "minimum" in properties[f]
        assert properties[f]["minimum"] == 1
        assert "maximum" in properties[f]
        assert properties[f]["maximum"] == 10

        f = "mylist"
        assert f in properties
        # "items": {
        # "type": "string"
        # },
        # "type": "array"

        f = "mylist2"
        assert f in properties
        # "items": {
        # "type": "integer"
        # },
        # "type": "array"

        f = "mylist3"
        assert f in properties
        # "items": {},
        # "type": "array"

        f = "mymaxstr"
        assert f in properties
        # "maxLength": 7,
        # "type": "string"

        f = "mynested"
        assert f in properties
        # "$ref": "#/definitions/Nested"

        f = "myselect"
        assert f in properties
        # "enum": [
        #     "a",
        #     "b"
        # ],
        # "type": "string"

        f = "myselect2"
        assert f in properties
        # "enum": [
        #     "a",
        #     "b"
        # ],
        # "type": "string"

        f = "mystr"
        assert f in properties
        # "minLength": 4,
        # "type": "string"
