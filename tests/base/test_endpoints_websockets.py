# -*- coding: utf-8 -*-
from restapi.tests import BaseTests, API_URI
from restapi.services.detect import detector
# from restapi.services.detect import detector
from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_websockets(self, client, fake):

        if not detector.check_availability('pushpin'):
            log.warning("Skipping websockets test: pushpin service not available")
            return False

        channel = fake.pystr()
        endpoint = API_URI + '/socket/' + channel
        r = client.post(endpoint)
        assert r.status_code == 401

        r = client.put(endpoint)
        assert r.status_code == 401

        headers, _ = self.do_login(client, None, None)
        headers['Content-Type'] = 'application/websocket-events'

        r = client.post(endpoint, headers=headers)
        assert r.status_code == 400
        error = 'Cannot decode websocket request: invalid in_event'
        assert self.get_content(r) == error

        data = b'\r\n'
        r = client.post(endpoint, data=data, headers=headers)
        assert r.status_code == 400
        error = 'Cannot understand websocket request'
        assert self.get_content(r) == error

        data = b'OPEN'
        r = client.post(endpoint, data=data, headers=headers)
        assert r.status_code == 400
        error = 'Cannot decode websocket request: invalid format'
        assert self.get_content(r) == error

        data = b'XYZ\r\n'
        r = client.post(endpoint, data=data, headers=headers)
        assert r.status_code == 400
        error = 'Cannot understand websocket request'
        assert self.get_content(r) == error

        data = b'OPEN\r\n'
        r = client.post(endpoint, data=data, headers=headers)
        assert r.status_code == 200
        content = r.data.decode('utf-8').split("\n")
        assert len(content) >= 3
        assert content[0] == 'OPEN\r'
        assert content[1] == 'TEXT 3a\r'
        assert content[2] == 'c:{"channel": "%s", "type": "subscribe"}\r' % channel
        assert 'Sec-WebSocket-Extensions' in r.headers
        assert r.headers.get('Sec-WebSocket-Extensions') == 'grip'

        r = client.put(endpoint, headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == 'Message received: True'

        # send message on a different channel
        channel = fake.pystr()
        endpoint = API_URI + '/socket/' + channel
        r = client.put(endpoint, headers=headers)
        assert r.status_code == 200
        assert self.get_content(r) == 'Message received: True'
