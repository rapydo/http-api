import pytest
from faker import Faker

from restapi.connectors import Connector
from restapi.tests import API_URI, BaseTests, FlaskClient


@pytest.mark.skipif(
    not Connector.check_availability("pushpin"),
    reason="This test needs pushpin to be available",
)
class TestApp(BaseTests):
    def test_websockets(self, client: FlaskClient, faker: Faker) -> None:

        channel = faker.pystr()
        r = client.post(f"{API_URI}/socket/{channel}")
        assert r.status_code == 401

        r = client.put(f"{API_URI}/socket/{channel}/1")
        assert r.status_code == 401

        headers, _ = self.do_login(client, None, None)
        assert headers is not None
        headers["Content-Type"] = "application/websocket-events"

        r = client.post(f"{API_URI}/socket/{channel}", headers=headers)
        assert r.status_code == 400
        error = "Cannot decode websocket request: invalid in_event"
        assert self.get_content(r) == error

        data = b"\r\n"
        r = client.post(f"{API_URI}/socket/{channel}", data=data, headers=headers)
        assert r.status_code == 400
        error = "Cannot understand websocket request"
        assert self.get_content(r) == error

        data = b"OPEN"
        r = client.post(f"{API_URI}/socket/{channel}", data=data, headers=headers)
        assert r.status_code == 400
        error = "Cannot decode websocket request: invalid format"
        assert self.get_content(r) == error

        data = b"XYZ\r\n"
        r = client.post(f"{API_URI}/socket/{channel}", data=data, headers=headers)
        assert r.status_code == 400
        error = "Cannot understand websocket request"
        assert self.get_content(r) == error

        data = b"OPEN\r\n"
        r = client.post(f"{API_URI}/socket/{channel}", data=data, headers=headers)
        assert r.status_code == 200
        content = r.data.decode("utf-8").split("\n")
        assert len(content) >= 3
        assert content[0] == "OPEN\r"
        assert content[1] == "TEXT 3a\r"
        assert content[2] == 'c:{"channel": "%s", "type": "subscribe"}\r' % channel
        assert "Sec-WebSocket-Extensions" in r.headers
        assert r.headers.get("Sec-WebSocket-Extensions") == "grip"

        r = client.put(f"{API_URI}/socket/{channel}/1", headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == "Message received: True (sync=True)"

        r = client.put(f"{API_URI}/socket/{channel}/0", headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == "Message received: True (sync=False)"

        # send message on a different channel
        channel = faker.pystr()
        r = client.put(f"{API_URI}/socket/{channel}/1", headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == "Message received: True (sync=True)"

        r = client.post(f"{API_URI}/stream/{channel}", headers=headers)
        assert r.status_code == 200
        content = r.data.decode("utf-8")
        assert content == "Stream opened, prepare yourself!\n"
        assert "Grip-Hold" in r.headers
        assert r.headers["Grip-Hold"] == "stream"
        assert "Grip-Channel" in r.headers

        r = client.put(f"{API_URI}/stream/{channel}/1", headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == "Message received: True (sync=True)"

        r = client.put(f"{API_URI}/stream/{channel}/0", headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == "Message received: True (sync=False)"
