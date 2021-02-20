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
