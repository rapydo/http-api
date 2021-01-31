from faker import Faker

from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_tokens(self, client: FlaskClient, fake: Faker) -> None:

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
        if len(content) < 3:  # pragma: no cover

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
                # Sort_by emitted or other date cannot be done, because mysql truncate
                # the date, so that sort can't be predicted [several dates are reported]
                # as the same. Let's use a certainly unique field like uuid
                "sort_by": "uuid",
            },
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        default_sort = self.get_content(r)
        assert len(default_sort) >= 2

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={
                "page": 1,
                "size": 20,
                "input_filter": "1",
                # Sort_by emitted or other date cannot be done, because mysql truncate
                # the date, so that sort can't be predicted [several dates are reported]
                # as the same. Let's use a certainly unique field like uuid
                "sort_by": "uuid",
                "sort_order": "asc",
            },
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        asc_sort = self.get_content(r)
        assert len(asc_sort) >= 2
        assert default_sort[0]["token"] == asc_sort[0]["token"]
        assert default_sort[-1]["token"] == asc_sort[-1]["token"]

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={
                "page": 1,
                "size": 20,
                "input_filter": "1",
                # Sort_by emitted or other date cannot be done, because mysql truncate
                # the date, so that sort can't be predicted [several dates are reported]
                # as the same. Let's use a certainly unique field like uuid
                "sort_by": "uuid",
                "sort_order": "desc",
            },
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        desc_sort = self.get_content(r)
        # Results of desc_sort can't be compared with previous contents
        # It may only be done if we were able to retrieve all tokens, in this case the
        # first desc will be the last asc... But we cannot ensure to be able to always
        # retrieve all tokens.
        assert len(desc_sort) >= 2
        # At least they should be different
        # assert asc_sort[0] != desc_sort[0]
        # assert asc_sort[-1] != desc_sort[-1]

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
        # This will be used to authenticate the requests. A new last_tokens is required
        # because the login could invalidate previous tokens due to password expiration
        last_tokens_header, last_token = self.do_login(client, None, None)
        # This will be used as target for deletion
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
