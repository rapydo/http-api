from typing import Any, Dict

from faker import Faker

from restapi.connectors import Connector
from restapi.tests import API_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_sendmail(self, client: FlaskClient, faker: Faker) -> None:

        # mailmock is always enabled during core tests
        if not Connector.check_availability("smtp"):  # pragma: no cover
            log.warning("Skipping admin send mail tests")
            return

        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/admin/mail", headers=headers)
        assert r.status_code == 405

        r = client.put(f"{API_URI}/admin/mail", headers=headers)
        assert r.status_code == 405

        r = client.patch(f"{API_URI}/admin/mail", headers=headers)
        assert r.status_code == 405

        r = client.delete(f"{API_URI}/admin/mail", headers=headers)
        assert r.status_code == 405

        data: Dict[str, Any] = {}
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 400

        data["subject"] = faker.pystr()
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 400

        data["body"] = faker.text()
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 400

        data["to"] = faker.pystr()
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 400

        data["to"] = faker.ascii_email()
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 204

        data["cc"] = faker.pystr()
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 400

        data["cc"] = [faker.ascii_email()]
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 204

        data["cc"] = faker.ascii_email()
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 204

        data["cc"] = f"{faker.ascii_email()},{faker.pystr()}"
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 400

        data["cc"] = f"{faker.ascii_email()},{faker.ascii_email()}"
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 204

        data["bcc"] = faker.pystr()
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 400

        data["bcc"] = [faker.ascii_email()]
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 204

        data["bcc"] = f"{faker.ascii_email()},{faker.pystr()}"
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 400

        data["bcc"] = f"{faker.ascii_email()},{faker.ascii_email()}"
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 204

        mail = self.read_mock_email()

        body = mail.get("body")
        headers = mail.get("headers")
        assert body is not None
        assert headers is not None
        # Subject: is a key in the MIMEText
        assert f"Subject: {data['subject']}" in headers
        ccs = mail.get("cc")
        assert ccs[0] == data["to"]
        assert ccs[1] == data["cc"].split(",")
        assert ccs[2] == data["bcc"].split(",")

        self.delete_mock_email()
        data = {
            "subject": faker.pystr(),
            "body": "TEST EMAIL BODY",
            "to": faker.ascii_email(),
        }
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 204
        mail = self.read_mock_email()
        body = mail.get("body")
        assert "TEST EMAIL BODY" in body

        self.delete_mock_email()
        data = {
            "subject": faker.pystr(),
            "body": "TEST EMAIL <b>HTML</b> BODY",
            "to": faker.ascii_email(),
        }
        r = client.post(f"{API_URI}/admin/mail", data=data, headers=headers)
        assert r.status_code == 204
        mail = self.read_mock_email()
        body = mail.get("body")
        assert "TEST EMAIL <b>HTML</b> BODY" in body
