from restapi.tests import BaseTests, API_URI, AUTH_URI
# from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_tokens(self, client):

        last_token = None
        last_tokens_header = None
        token_id = None

        for _ in range(5):
            header, token = self.do_login(client, None, None)
            last_tokens_header = header
            last_token = token

        endpoint = AUTH_URI + '/tokens'

        # TEST GET ALL TOKENS
        r = client.get(endpoint, headers=last_tokens_header)
        content = self.get_content(r)
        assert r.status_code == 200
        # By creating 5 tokens we expected at least 3 tokens
        # If password expires at third tokens the first and second will be
        # invalidated => exactly 3 tokens will be created at the end
        assert len(content) >= 3

        # save a token to be used for further tests
        for c in content:
            if c["token"] == last_token:
                continue
            token_id = c["id"]

        # SINGLE TOKEN IS NOT ALLOWED
        endpoint_single = f"{endpoint}/{token_id}"
        r = client.get(endpoint_single, headers=last_tokens_header)
        assert r.status_code == 405

        # TEST GET ALL TOKENS (expected at least NUM_TOKENS)
        r = client.get(API_URI + "/admin/tokens", headers=last_tokens_header)
        assert r.status_code == 200
        assert len(self.get_content(r)) >= NUM_TOKENS

        # DELETE INVALID TOKEN
        r = client.delete(
            API_URI + "/admin/tokens/xyz",
            headers=last_tokens_header
        )
        assert r.status_code == 404

        endpoint_single = f"{endpoint}/{token_id}"

        # TEST DELETE OF A SINGLE TOKEN
        r = client.delete(endpoint_single, headers=last_tokens_header)
        assert r.status_code == 204

        # TEST AN ALREADY DELETED TOKEN
        r = client.delete(endpoint_single, headers=last_tokens_header)
        assert r.status_code == 401

        # TEST INVALID DELETE OF A SINGLE TOKEN
        r = client.delete(endpoint + "/0", headers=last_tokens_header)
        assert r.status_code == 401

        # TEST TOKEN IS STILL VALID
        r = client.get(endpoint, headers=last_tokens_header)
        assert r.status_code == 200
