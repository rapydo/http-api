from restapi.env import Env
from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_GET_specs(self, client: FlaskClient) -> None:
        r = client.get(f"{API_URI}/specs")
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, dict)
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

        if Env.get_bool("AUTH_ENABLE"):
            assert "securityDefinitions" in content
            assert "Bearer" in content["securityDefinitions"]
        else:
            assert "securityDefinitions" not in content

        if Env.get_bool("AUTH_ENABLE"):
            headers, _ = self.do_login(client, None, None)
            r = client.get(f"{API_URI}/specs", headers=headers)
            assert r.status_code == 200
            content = self.get_content(r)
            assert isinstance(content, dict)
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

        # IMPORT: if authentication is enabled with content is replaced by the full spec
        # Otherwise the if branch is not execute and the basic spec is used

        # Based on the definition of InputSchema in test_inputs.py
        assert "/api/tests/inputs" in content["paths"]
        assert "post" in content["paths"]["/api/tests/inputs"]
        endpoint = content["paths"]["/api/tests/inputs"]["post"]
        assert "parameters" in endpoint
        assert isinstance(endpoint["parameters"], list)
        assert len(endpoint["parameters"]) == 1
        assert "schema" in endpoint["parameters"][0]
        assert "$ref" in endpoint["parameters"][0]["schema"]
        assert endpoint["parameters"][0]["schema"]["$ref"] == "#/definitions/Input"

        assert "Input" in content["definitions"]

        schema = content["definitions"]["Input"]
        assert "properties" in schema
        assert "required" in schema
        assert "type" in schema
        assert schema["type"] == "object"

        assert "MYDATE" in schema["required"]
        assert "MYDATETIME" in schema["required"]
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

        properties = schema["properties"]
        f = "MYDATE"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "string"
        assert "format" in properties[f]
        assert properties[f]["format"] == "date"
        # min and max not set for this example
        assert "x-minimum" not in properties[f]
        assert "x-maximum" not in properties[f]

        f = "MYDATETIME"
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

        # string[]
        f = "mylist"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "array"
        assert "items" in properties[f]
        assert "type" in properties[f]["items"]
        assert len(properties[f]["items"]) == 1
        assert properties[f]["items"]["type"] == "string"

        # int[]
        f = "mylist2"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "array"
        assert "items" in properties[f]
        assert "type" in properties[f]["items"]
        assert len(properties[f]["items"]) == 1
        assert properties[f]["items"]["type"] == "integer"

        # List of custom field
        f = "mylist3"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "array"
        assert "items" in properties[f]
        # no property specified for custom fields... apispec is unable to convert it
        assert len(properties[f]["items"]) == 0

        f = "mymaxstr"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "string"
        assert "maxLength" in properties[f]
        assert properties[f]["maxLength"] == 7

        # Normal Nested are assigned to $ref key
        f = "mynested"
        assert f in properties
        assert "$ref" in properties[f]
        assert properties[f]["$ref"] == "#/definitions/Nested"

        # Nullable Nested are assigned to allOf key
        f = "mynullablenested"
        assert f in properties
        assert "allOf" in properties[f]
        assert "$ref" in properties[f]["allOf"][0]
        assert properties[f]["allOf"][0]["$ref"] == "#/definitions/Nested"
        assert "x-nullable" in properties[f]
        assert properties[f]["x-nullable"] is True

        f = "myselect"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "string"
        assert "enum" in properties[f]
        assert isinstance(properties[f]["enum"], list)
        assert len(properties[f]["enum"]) == 2
        assert properties[f]["enum"][0] == "a"
        assert properties[f]["enum"][1] == "b"

        f = "myselect2"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "string"
        assert "enum" in properties[f]
        assert isinstance(properties[f]["enum"], list)
        assert len(properties[f]["enum"]) == 2
        assert properties[f]["enum"][0] == "a"
        assert properties[f]["enum"][1] == "b"

        f = "mystr"
        assert f in properties
        assert "type" in properties[f]
        assert properties[f]["type"] == "string"
        assert "minLength" in properties[f]
        assert properties[f]["minLength"] == 4
