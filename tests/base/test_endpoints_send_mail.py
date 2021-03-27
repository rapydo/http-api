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

        r = client.post(f"{API_URI}/group/users", data={}, headers=headers)
        assert r.status_code == 400
