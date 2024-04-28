from typing import Any

import pytest
from faker import Faker

from restapi.connectors import Connector
from restapi.env import Env
from restapi.tests import API_URI, BaseTests, FlaskClient


@pytest.mark.skipif(
    not Connector.check_availability("smtp") or not Env.get_bool("AUTH_ENABLE"),
    reason="This test needs smtp and auth to be available",
)
class TestApp(BaseTests):
    def test_sendmail(self, client: FlaskClient, faker: Faker) -> None:
        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/admin/mail", headers=headers)
        assert r.status_code == 405

        r = client.put(f"{API_URI}/admin/mail", headers=headers)
        assert r.status_code == 405

        r = client.patch(f"{API_URI}/admin/mail", headers=headers)
        assert r.status_code == 405

        r = client.delete(f"{API_URI}/admin/mail", headers=headers)
        assert r.status_code == 405

        data: dict[str, Any] = {"dry_run": False}
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 400

        data["subject"] = faker.pystr()
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 400

        data["body"] = faker.text()
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 400

        data["to"] = faker.pystr()
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 400

        data["to"] = faker.ascii_email()
        data["body"] = "TEST EMAIL BODY"
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 204

        mail = self.read_mock_email()
        body = mail.get("body", "")
        assert "TEST EMAIL BODY" in body

        data["dry_run"] = True
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 200

        response = self.get_content(r)
        assert isinstance(response, dict)
        assert "html_body" in response
        assert "plain_body" in response
        assert "subject" in response
        assert "to" in response
        assert "cc" in response
        assert "bcc" in response

        data["dry_run"] = False

        data["body"] = "TEST EMAIL <b>HTML</b> BODY"
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 204
        mail = self.read_mock_email()
        body = mail.get("body", "")
        assert "TEST EMAIL <b>HTML</b> BODY" in body

        data["dry_run"] = True
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 200

        response = self.get_content(r)
        assert isinstance(response, dict)
        assert "html_body" in response
        assert "plain_body" in response
        assert "subject" in response
        assert "to" in response
        assert "cc" in response
        assert "bcc" in response

        data["dry_run"] = False

        data["body"] = faker.text()
        data["cc"] = faker.pystr()
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 400

        data["cc"] = faker.ascii_email()
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 204

        data["cc"] = f"{faker.ascii_email()},{faker.pystr()}"
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 400

        data["cc"] = f"{faker.ascii_email()},{faker.ascii_email()}"
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 204

        data["bcc"] = faker.pystr()
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 400

        data["bcc"] = f"{faker.ascii_email()},{faker.pystr()}"
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 400

        data["bcc"] = f"{faker.ascii_email()},{faker.ascii_email()}"
        r = client.post(f"{API_URI}/admin/mail", json=data, headers=headers)
        assert r.status_code == 204

        mail = self.read_mock_email()

        body = mail.get("body", "")
        email_headers = mail.get("headers", "")
        assert body is not None
        assert email_headers is not None
        # Subject: is a key in the MIMEText
        assert f"Subject: {data['subject']}" in email_headers
        ccs = mail.get("cc", [])
        assert ccs[0] == data["to"]
        assert ccs[1] == data["cc"].split(",")[0]
        assert ccs[2] == data["cc"].split(",")[1]
        assert ccs[3] == data["bcc"].split(",")[0]
        assert ccs[4] == data["bcc"].split(",")[1]
