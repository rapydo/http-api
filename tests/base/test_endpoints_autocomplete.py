import random

import orjson

from restapi.tests import API_URI, SERVER_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_autocomplete(self, client: FlaskClient) -> None:
        # This test verifies that buildData is always able to randomly create
        # valid inputs for endpoints with inputs defined by marshamallow schemas
        schema = self.get_dynamic_input_schema(client, "tests/autocomplete", {})

        assert schema[0]["key"] == "elements"
        assert schema[0]["type"] == "string[]"
        assert "autocomplete_endpoint" in schema[0]
        assert "autocomplete_id_bind" in schema[0]
        assert "autocomplete_label_bind" in schema[0]
        assert "autocomplete_show_id" in schema[0]
        assert schema[0]["autocomplete_endpoint"] == "/api/tests/autocomplete"
        assert schema[0]["autocomplete_id_bind"] == "my_id"
        assert schema[0]["autocomplete_label_bind"] == "my_label"
        assert schema[0]["autocomplete_show_id"] is True

        autocomplete_endpoint = f"{SERVER_URI}{schema[0]['autocomplete_endpoint']}"

        r = client.get(f"{autocomplete_endpoint}/nobody")
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 0

        r = client.get(f"{autocomplete_endpoint}/oliver")
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) > 0
        assert schema[0]["autocomplete_id_bind"] in content[0]
        assert schema[0]["autocomplete_label_bind"] in content[0]

        r = client.get(f"{autocomplete_endpoint}/s the")
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) > 0
        assert schema[0]["autocomplete_id_bind"] in content[0]
        assert schema[0]["autocomplete_label_bind"] in content[0]

        rand = random.SystemRandom()

        data = []
        for _ in range(0, 3):
            element = rand.choice(content)
            data.append(element[schema[0]["autocomplete_id_bind"]])

        # put accepts a single id provided by the autocomplete endpoint
        r = client.put(f"{API_URI}/tests/autocomplete", json={"element": data[0]})
        assert r.status_code == 204

        # post accepts a list of ids provided by the autocomplete endpoint
        r = client.post(
            f"{API_URI}/tests/autocomplete",
            json={"elements": orjson.dumps(data).decode("UTF8")},
        )
        assert r.status_code == 204
