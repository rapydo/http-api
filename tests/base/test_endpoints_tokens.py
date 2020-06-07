from restapi.tests import API_URI, AUTH_URI, BaseTests

# from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_tokens(self, client):

        last_token = None
        last_tokens_header = None
        token_id = None

        for _ in range(3):
            header, token = self.do_login(client, None, None)
            last_tokens_header = header
            last_token = token

        # TEST GET ALL TOKENS
        r = client.get(f"{AUTH_URI}/tokens", headers=last_tokens_header)
        content = self.get_content(r)
        assert r.status_code == 200

        # Probably due to password expiration:
        # change password invalidated tokens created before
        # => create tokens again
        if len(content) < 3:

            for _ in range(3):
                header, token = self.do_login(client, None, None)
                last_tokens_header = header
                last_token = token

            # TEST GET ALL TOKENS
            r = client.get(f"{AUTH_URI}/tokens", headers=last_tokens_header)
            content = self.get_content(r)
            assert r.status_code == 200
            assert len(content) >= 3

        # save a token to be used for further tests
        for c in content:
            if c["token"] == last_token:
                continue
            token_id = c["id"]

        # SINGLE TOKEN IS NOT ALLOWED
        r = client.get(f"{AUTH_URI}/tokens/{token_id}", headers=last_tokens_header)
        assert r.status_code == 405

        # TEST GET ALL TOKENS
        r = client.get(f"{API_URI}/admin/tokens", headers=last_tokens_header)
        assert r.status_code == 200
        assert len(self.get_content(r)) >= 3

        # DELETE INVALID TOKEN
        r = client.delete(f"{API_URI}/admin/tokens/xyz", headers=last_tokens_header)
        assert r.status_code == 404

        # TEST DELETE OF A SINGLE TOKEN
        r = client.delete(f"{AUTH_URI}/tokens/{token_id}", headers=last_tokens_header)
        assert r.status_code == 204

        # TEST AN ALREADY DELETED TOKEN
        r = client.delete(f"{AUTH_URI}/tokens/{token_id}", headers=last_tokens_header)
        assert r.status_code == 401

        # TEST INVALID DELETE OF A SINGLE TOKEN
        r = client.delete(f"{AUTH_URI}/tokens/0", headers=last_tokens_header)
        assert r.status_code == 401

        # TEST TOKEN IS STILL VALID
        r = client.get(f"{AUTH_URI}/tokens", headers=last_tokens_header)
        assert r.status_code == 200

        # TEST TOKEN DELETION VIA ADMIN ENDPOINT
        header, token = self.do_login(client, None, None)

        # TEST GET ALL TOKENS
        r = client.get(f"{AUTH_URI}/tokens", headers=last_tokens_header)
        content = self.get_content(r)
        assert r.status_code == 200

        token_id = None
        for c in content:
            if c["token"] == token:
                continue
            token_id = c["id"]

        assert token_id is not None

        r = client.delete(
            f"{API_URI}/admin/tokens/{token_id}", headers=last_tokens_header
        )
        assert r.status_code == 204

        r = client.delete(
            f"{API_URI}/admin/tokens/{token_id}", headers=last_tokens_header
        )
        assert r.status_code == 404
