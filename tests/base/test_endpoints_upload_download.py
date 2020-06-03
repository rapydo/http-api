import io
from restapi.tests import BaseTests, API_URI


class TestUploadAndDownload(BaseTests):

    def test_upload(self, client, fake):

        # Avoid chinese filename for now... let's simplify the tests
        # self.fname = fake.file_name()
        self.fname = f"{fake.pystr()}.{fake.file_extension()}"
        self.fcontent = fake.paragraph()

        self.save("fname", self.fname)
        self.save("fcontent", self.fcontent)

        r = client.put(
            f'{API_URI}/tests/upload',
            data={
                "file": (io.BytesIO(str.encode(self.fcontent)), self.fname),
                "force": True
            }
        )
        assert r.status_code == 200

        r = client.put(
            f'{API_URI}/tests/upload',
            data={
                "file": (io.BytesIO(str.encode(self.fcontent)), self.fname),
            }
        )
        assert r.status_code == 400
        err = f"File '{self.fname}' already exists, use force parameter to overwrite"
        assert self.get_content(r) == err

        r = client.put(
            f'{API_URI}/tests/upload',
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
        assert meta.get('charset') is not None
        assert meta.get('type') is not None

    def test_download(self, client, fake):

        self.fname = self.get("fname")
        self.fcontent = self.get("fcontent")

        r = client.get(f'{API_URI}/tests/download/doesnotexist')
        assert r.status_code == 400

        # no filename provided
        r = client.get(f'{API_URI}/tests/download')
        assert r.status_code == 400

        r = client.get(f'{API_URI}/tests/download/{self.fname}')
        assert r.status_code == 200
        content = r.data.decode('utf-8')
        assert content == self.fcontent

        new_content = 'new content'
        r = client.put(
            f'{API_URI}/tests/upload',
            data={
                "file": (io.BytesIO(str.encode(new_content)), self.fname),
                "force": True
            }
        )
        assert r.status_code == 200

        r = client.get(f'{API_URI}/tests/download/{self.fname}')
        assert r.status_code == 200
        content = r.data.decode('utf-8')
        assert content != self.fcontent
        assert content == new_content

        r = client.get(f'{API_URI}/tests/download/{self.fname}', data={'stream': True})
        assert r.status_code == 200
        content = r.data.decode('utf-8')
        assert content == new_content

        r = client.get(f'{API_URI}/tests/download/doesnotexist', data={'stream': True})
        assert r.status_code == 400

    def test_chunked(self, client, fake):

        self.fname = self.get("fname")
        self.fcontent = self.get("fcontent")

        r = client.post(f'{API_URI}/tests/upload', data={'force': True})
        assert r.status_code == 400

        data = {
            'force': True,
            'name': 'fixed.filename',
            'size': '999',
            'mimeType': 'application/zip',
            'lastModified': 1590302749209
        }
        r = client.post(f'{API_URI}/tests/upload', data=data)
        assert r.status_code == 201
        assert self.get_content(r) == ''

        with io.StringIO(fake.text()) as f:
            r = client.put(
                f'{API_URI}/tests/upload/chunked',
                data=f
            )
        assert r.status_code == 400
        assert self.get_content(r) == 'Invalid request'

        with io.StringIO(fake.text()) as f:
            r = client.put(
                f'{API_URI}/tests/upload/chunked',
                data=f,
                headers={
                    "Content-Range": '!'
                }
            )
        assert r.status_code == 400
        assert self.get_content(r) == 'Invalid request'

        up_data = fake.pystr(min_chars=24, max_chars=48)
        STR_LEN = len(up_data)
        with io.StringIO(up_data[0:5]) as f:
            r = client.put(
                f'{API_URI}/tests/upload/chunked',
                data=f,
                headers={
                    "Content-Range": f'bytes 0-5/{STR_LEN}'
                }
            )
        assert r.status_code == 206
        assert self.get_content(r) == 'partial'

        with io.StringIO(up_data[5:]) as f:
            r = client.put(
                f'{API_URI}/tests/upload/chunked',
                data=f,
                headers={
                    "Content-Range": f'bytes 5-{STR_LEN}/{STR_LEN}'
                }
            )
        assert r.status_code == 200
        c = self.get_content(r)
        assert c.get('filename') is not None
        uploaded_filename = c.get('filename')
        meta = c.get('meta')
        assert meta is not None
        assert meta.get('charset') == 'us-ascii'
        assert meta.get('type') == 'text/plain'

        r = client.get(f'{API_URI}/tests/download/{uploaded_filename}')
        assert r.status_code == 200
        content = r.data.decode('utf-8')
        assert content == up_data

        r = client.get(
            f'{API_URI}/tests/download/{uploaded_filename}'
        )
        assert r.status_code == 200
        content = r.data.decode('utf-8')
        assert content == up_data

        r = client.get(
            f'{API_URI}/tests/download/{uploaded_filename}',
            headers={'Range': ''}
        )
        assert r.status_code == 416

        r = client.get(
            f'{API_URI}/tests/download/{uploaded_filename}',
            headers={'Range': f'0-{STR_LEN - 1}'}
        )
        assert r.status_code == 416

        # Back-compatibility fix. This is due to the backendirods container
        # that forces the installation of Werkzeug 0.16.1 instead of 1.0+
        from werkzeug import __version__ as werkzeug_version

        old_werkzeug = werkzeug_version == "0.16.1"
        r = client.get(
            f'{API_URI}/tests/download/{uploaded_filename}',
            headers={'Range': 'bytes=0-9999999999999999'}
        )
        if old_werkzeug:
            assert r.status_code == 200
        else:
            assert r.status_code == 206

        r = client.get(
            f'{API_URI}/tests/download/{uploaded_filename}',
            headers={'Range': 'bytes=0-4'}
        )
        assert r.status_code == 206
        content = r.data.decode('utf-8')
        assert content == up_data[0:5]

        r = client.get(
            f'{API_URI}/tests/download/{uploaded_filename}',
            headers={'Range': f'bytes=5-{STR_LEN - 1}'}
        )
        assert r.status_code == 206
        content = r.data.decode('utf-8')
        assert content == up_data[5:]

        r = client.get(
            f'{API_URI}/tests/download/{uploaded_filename}',
            headers={'Range': f'bytes=0-{STR_LEN - 1}'}
        )
        if old_werkzeug:
            assert r.status_code == 200
        else:
            assert r.status_code == 206
        content = r.data.decode('utf-8')
        assert content == up_data

        # Send a new string as content file. Will be appended as prefix
        up_data2 = fake.pystr(min_chars=24, max_chars=48)
        STR_LEN = len(up_data2)
        with io.StringIO(up_data) as f:
            r = client.put(
                f'{API_URI}/tests/upload/chunked',
                data=f,
                headers={
                    "Content-Range": f'bytes */{STR_LEN}'
                }
            )
        assert r.status_code == 200
        c = self.get_content(r)
        assert c.get('filename') is not None
        uploaded_filename = c.get('filename')
        meta = c.get('meta')
        assert meta is not None
        assert meta.get('charset') == 'us-ascii'
        assert meta.get('type') == 'text/plain'

        r = client.get(f'{API_URI}/tests/download/{uploaded_filename}')
        assert r.status_code == 200
        content = r.data.decode('utf-8')
        assert content == up_data2 + up_data

        data['force'] = False
        r = client.post(f'{API_URI}/tests/upload', data=data)
        assert r.status_code == 400
        err = f"File '{uploaded_filename}' already exists"
        assert self.get_content(r) == err

        data['force'] = True
        r = client.post(f'{API_URI}/tests/upload', data=data)
        assert r.status_code == 201
        assert self.get_content(r) == ''
