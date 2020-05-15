# -*- coding: utf-8 -*-
import io
from restapi.tests import BaseTests, API_URI


class TestUploadAndDownload(BaseTests):
    fname = "myfile.txt"
    fcontent = "v"

    def test_upload(self, client):

        r = client.put(
            API_URI + '/tests/upload',
            data={
                "file": (io.BytesIO(str.encode(self.fcontent)), self.fname),
                "force": True
            }
        )
        assert r.status_code == 200

        r = client.put(
            API_URI + '/tests/upload',
            data={
                "file": (io.BytesIO(str.encode(self.fcontent)), self.fname),
            }
        )
        assert r.status_code == 400
        err = "File '{}' already exists, use force parameter to overwrite".format(
            self.fname
        )
        assert self.get_content(r) == err

        r = client.put(
            API_URI + '/tests/upload',
            data={
                "file": (io.BytesIO(str.encode(self.fcontent)), self.fname),
                "force": True
            }
        )
        assert r.status_code == 200

        c = self.get_content(r)
        assert c.get('filename') == self.fname
        meta = c.get('meta')
        assert meta is not None
        assert meta.get('charset') == 'binary'
        assert meta.get('type') == 'application/octet-stream'

        r = client.post(API_URI + '/tests/upload')
        assert r.status_code == 201
        assert self.get_content(r) == ''

        # r.headers should contain "Location": url
        # assert r.headers ??

    def test_download(self, client):

        endpoint = API_URI + '/tests/download/'

        r = client.get(endpoint + 'doesnotexist')
        assert r.status_code == 400

        # no filename provided
        r = client.get(endpoint)
        assert r.status_code == 400

        r = client.get(endpoint + self.fname)
        assert r.status_code == 200
        content = r.data.decode('utf-8')
        assert content == self.fcontent

        new_content = 'new content'
        r = client.put(
            API_URI + '/tests/upload',
            data={
                "file": (io.BytesIO(str.encode(new_content)), self.fname),
                "force": True
            }
        )
        assert r.status_code == 200

        r = client.get(endpoint + self.fname)
        assert r.status_code == 200
        content = r.data.decode('utf-8')
        assert content != self.fcontent
        assert content == new_content

        r = client.get(endpoint + self.fname, data={'stream': True})
        assert r.status_code == 200

        r = client.get(endpoint + 'doesnotexist', data={'stream': True})
        assert r.status_code == 400
