from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_inputs(self, client: FlaskClient) -> None:

        # This test verifies that buildData is always able to randomly create
        # valid inputs for endpoints with inputs defined by marshamallow schemas
        schema = self.getDynamicInputSchema(client, "tests/inputs", {})
        data = self.buildData(schema)

        r = client.post(f"{API_URI}/tests/inputs", data=data)
        assert r.status_code == 204
