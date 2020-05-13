# -*- coding: utf-8 -*-
from restapi.tests import BaseTests, API_URI, AUTH_URI
# from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_tokens(self, client):

        # CREATING 3 TOKENS
        NUM_TOKENS = 3
        first_token = None
        tokens_header = None
        token_id = None

        for _ in range(NUM_TOKENS):
            header, token = self.do_login(client, None, None)
            if tokens_header is None:
                tokens_header = header
                first_token = token

        endpoint = AUTH_URI + '/tokens'

        # TEST GET ALL TOKENS (expected at least NUM_TOKENS)
        r = client.get(endpoint, headers=tokens_header)
        content = self.get_content(r)
        assert r.status_code == 200
        assert len(content) >= NUM_TOKENS

        # save a token to be used for further tests
        for c in content:
            if c["token"] == first_token:
                continue
            token_id = c["id"]

        # SINGLE TOKEN IS NOT ALLOWED
        endpoint_single = "{}/{}".format(endpoint, token_id)
        r = client.get(endpoint_single, headers=tokens_header)
        assert r.status_code == 405

        # TEST GET ALL TOKENS (expected at least NUM_TOKENS)
        r = client.get(API_URI + "/admin/tokens", headers=tokens_header)
        assert r.status_code == 200
        assert len(self.get_content(r)) >= NUM_TOKENS

        # DELETE INVALID TOKEN
        r = client.delete(
            API_URI + "/admin/tokens/xyz",
            headers=tokens_header
        )
        assert r.status_code == 404

        endpoint_single = "{}/{}".format(endpoint, token_id)

        # TEST DELETE OF A SINGLE TOKEN
        r = client.delete(endpoint_single, headers=tokens_header)
        assert r.status_code == 204

        # TEST AN ALREADY DELETED TOKEN
        r = client.delete(endpoint_single, headers=tokens_header)
        assert r.status_code == 401

        # TEST INVALID DELETE OF A SINGLE TOKEN
        r = client.delete(endpoint + "/0", headers=tokens_header)
        assert r.status_code == 401

        # TEST TOKEN IS STILL VALID
        r = client.get(endpoint, headers=tokens_header)
        assert r.status_code == 200
