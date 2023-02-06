from faker import Faker

from restapi.env import Env
from restapi.tests import API_URI, AUTH_URI, BaseTests, FlaskClient
from restapi.utilities.logs import Events, log


class TestApp(BaseTests):
    def test_tokens(self, client: FlaskClient, faker: Faker) -> None:
        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping tokens tests")
            return

        last_token = None
        last_tokens_header = None
        token_id = None

        for _ in range(3):
            header, token = self.do_login(client, None, None)
            last_tokens_header = header
            last_token = token

        # TEST GET ALL TOKENS
        r = client.get(f"{AUTH_URI}/tokens", headers=last_tokens_header)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)

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
            assert r.status_code == 200
            content = self.get_content(r)
            assert isinstance(content, list)
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
        assert isinstance(content, dict)
        assert "total" in content
        assert content["total"] > 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"get_total": True, "input_filter": "1"},
            headers=last_tokens_header,
        )
        assert r.status_code == 206
        content = self.get_content(r)
        assert isinstance(content, dict)
        assert "total" in content
        assert content["total"] > 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"get_total": True, "input_filter": faker.pystr()},
            headers=last_tokens_header,
        )
        assert r.status_code == 206
        content = self.get_content(r)
        assert isinstance(content, dict)
        assert "total" in content
        assert content["total"] == 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"get_total": True, "page": 1, "size": 20},
            headers=last_tokens_header,
        )
        assert r.status_code == 206
        content = self.get_content(r)
        assert isinstance(content, dict)
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
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 0

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 1, "size": 2},
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) <= 2

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 1, "size": 20, "input_filter": "1"},
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) >= 1

        r = client.get(
            f"{API_URI}/admin/tokens",
            query_string={"page": 1, "size": 20, "input_filter": faker.pystr()},
            headers=last_tokens_header,
        )
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) == 0

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
        default_sort = self.get_content(r)
        assert isinstance(default_sort, list)
        assert len(default_sort) >= 2

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
        asc_sort = self.get_content(r)
        assert isinstance(asc_sort, list)
        assert len(asc_sort) >= 2
        assert default_sort[0]["token"] == asc_sort[0]["token"]
        assert default_sort[-1]["token"] == asc_sort[-1]["token"]

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
        desc_sort = self.get_content(r)
        assert isinstance(desc_sort, list)
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
        content = self.get_content(r)
        assert isinstance(content, list)
        assert len(content) >= 3

        # DELETE INVALID TOKEN
        r = client.delete(f"{API_URI}/admin/tokens/xyz", headers=last_tokens_header)
        assert r.status_code == 404

        # TEST DELETE OF A SINGLE TOKEN
        r = client.delete(f"{AUTH_URI}/tokens/{token_id}", headers=last_tokens_header)
        assert r.status_code == 204

        events = self.get_last_events(1)
        assert events[0].event == Events.delete.value
        assert events[0].target_type == "Token"
        # Tokens does not have a uuid...
        # assert events[0].target_id == token_id
        assert events[0].user == "-"
        assert events[0].url == f"/auth/tokens/{token_id}"

        # TEST AN ALREADY DELETED TOKEN
        r = client.delete(f"{AUTH_URI}/tokens/{token_id}", headers=last_tokens_header)
        assert r.status_code == 403

        # TEST INVALID DELETE OF A SINGLE TOKEN
        r = client.delete(f"{AUTH_URI}/tokens/0", headers=last_tokens_header)
        assert r.status_code == 403

        # TEST TOKEN IS STILL VALID
        r = client.get(f"{AUTH_URI}/tokens", headers=last_tokens_header)
        assert r.status_code == 200

        # user_header will be used as target for deletion
        # Always enabled in core tests
        if not Env.get_bool("MAIN_LOGIN_ENABLE"):  # pragma: no cover
            uuid = None
            user_header, token = self.do_login(client, None, None)
        else:
            uuid, data = self.create_user(client)
            user_header, token = self.do_login(client, data["email"], data["password"])

        r = client.get(f"{AUTH_URI}/status", headers=user_header)
        assert r.status_code == 200

        # TEST GET ALL TOKENS
        r = client.get(f"{AUTH_URI}/tokens", headers=user_header)
        assert r.status_code == 200
        content = self.get_content(r)
        assert isinstance(content, list)

        token_id = None
        for c in content:
            if c["token"] == token:
                token_id = c["id"]
                break

        assert token_id is not None

        last_tokens_header, _ = self.do_login(client, None, None)
        r = client.delete(
            f"{API_URI}/admin/tokens/{token_id}", headers=last_tokens_header
        )
        assert r.status_code == 204

        events = self.get_last_events(1)
        assert events[0].event == Events.delete.value
        assert events[0].target_type == "Token"
        # Tokens does not have a uuid...
        # assert events[0].target_id == token_id
        assert events[0].user == "-"
        assert events[0].url == f"/api/admin/tokens/{token_id}"

        r = client.delete(
            f"{API_URI}/admin/tokens/{token_id}", headers=last_tokens_header
        )
        assert r.status_code == 404

        r = client.get(f"{AUTH_URI}/status", headers=user_header)
        assert r.status_code == 401

        # Goodbye temporary user (if previously created)
        if uuid:
            self.delete_user(client, uuid)
