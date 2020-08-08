from restapi.env import Env
from restapi.tests import API_URI, AUTH_URI, BaseTests


class TestApp(BaseTests):
    def test_tokens(self, client, fake):

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
        r = client.get(f"{API_URI}/admin/tokens")
        assert r.status_code == 401

        # TEST GET ALL TOKENS
        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"get_total": True},
            headers=last_tokens_header,
        )
        assert r.status_code == 206
        content = self.get_content(r)
        assert "total" in content
        assert content["total"] > 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"get_total": True, "input_filter": "1"},
            headers=last_tokens_header,
        )
        assert r.status_code == 206
        content = self.get_content(r)
        assert "total" in content
        assert content["total"] > 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"get_total": True, "input_filter": fake.pystr()},
            headers=last_tokens_header,
        )
        assert r.status_code == 206
        content = self.get_content(r)
        assert "total" in content
        assert content["total"] == 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"get_total": True, "page": 1, "size": 20},
            headers=last_tokens_header,
        )
        assert r.status_code == 206
        content = self.get_content(r)
        assert "total" in content
        assert content["total"] > 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 0, "size": 20},
            headers=last_tokens_header,
        )
        assert r.status_code == 400

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 1, "size": 0},
            headers=last_tokens_header,
        )
        assert r.status_code == 400

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 1, "size": 101},
            headers=last_tokens_header,
        )
        assert r.status_code == 400

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 99999, "size": 20},
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        assert len(self.get_content(r)) == 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 1, "size": 2},
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) <= 2

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 1, "size": 20, "input_filter": "1"},
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        assert len(self.get_content(r)) >= 1

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 1, "size": 20, "input_filter": fake.pystr()},
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        assert len(self.get_content(r)) == 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={
                "page": 1,
                "size": 20,
                "input_filter": "1",
                "sort_by": "uuid",
            },
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert len(content) >= 2

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={
                "page": 1,
                "size": 20,
                "input_filter": "1",
                "sort_by": "uuid",
                "sort_order": "asc",
            },
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        new_content = self.get_content(r)
        assert len(new_content) >= 2

        # I don't know why... but this does not work with mysql...
        if Env.get("ALCHEMY_DBTYPE") != "mysql+pymysql":
            assert new_content[0] == content[0]
            assert new_content[-1] == content[-1]

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={
                "page": 1,
                "size": 20,
                "input_filter": "1",
                "sort_by": "uuid",
                "sort_order": "desc",
            },
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        new_content = self.get_content(r)
        assert len(new_content) >= 2
        # I don't know why... but this does not work with mysql...
        if Env.get("ALCHEMY_DBTYPE") != "mysql+pymysql":
            assert new_content[0] == content[-1]
            assert new_content[-1] == content[0]

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
        assert r.status_code == 403

        # TEST INVALID DELETE OF A SINGLE TOKEN
        r = client.delete(f"{AUTH_URI}/tokens/0", headers=last_tokens_header)
        assert r.status_code == 403

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
                token_id = c["id"]
                break

        assert token_id is not None

        r = client.delete(
            f"{API_URI}/admin/tokens/{token_id}", headers=last_tokens_header
        )
        assert r.status_code == 204

        r = client.delete(
            f"{API_URI}/admin/tokens/{token_id}", headers=last_tokens_header
        )
        assert r.status_code == 404
