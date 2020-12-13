from restapi.tests import API_URI, BaseTests


class TestApp(BaseTests):
    def test_inputs(self, client):

        schema = self.getDynamicInputSchema(client, "tests/inputs", {})
        data = self.buildData(schema)

        r = client.post(f"{API_URI}/tests/inputs", data=data)
        assert r.status_code == 204
