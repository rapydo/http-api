import io
import os

from faker import Faker

from restapi.config import UPLOAD_PATH
from restapi.tests import API_URI, BaseTests, FlaskClient


class TestUploadAndDownload(BaseTests):
    def test_upload(self, client: FlaskClient, faker: Faker) -> None:

        self.fcontent = faker.paragraph()
        self.save("fcontent", self.fcontent)
        # as defined in test_upload.py for normal uploads
        upload_folder = "fixsubfolder"

        self.fname = f"{faker.pystr()}.notallowed"

        r = client.put(
            f"{API_URI}/tests/upload",
            data={
                "file": (io.BytesIO(str.encode(self.fcontent)), self.fname),
                # By setting force False only txt files will be allowed for upload
                # Strange, but it is how the endpoint is configured to improve the tests
                "force": False,
            },
        )
        assert r.status_code == 400
        assert self.get_content(r) == "File extension not allowed"

        self.fname = f"{faker.pystr()}.not"

        r = client.put(
            f"{API_URI}/tests/upload",
            data={
                "file": (io.BytesIO(str.encode(self.fcontent)), self.fname),
                # By setting force False only txt files will be allowed for upload
                # Strange, but it is how the endpoint is configured to improve the tests
                "force": False,
            },
        )
        assert r.status_code == 400
        assert self.get_content(r) == "File extension not allowed"

        self.fname = f"{faker.pystr()}.txt"
        self.save("fname", self.fname)

        r = client.put(
            f"{API_URI}/tests/upload",
            data={
                "file": (io.BytesIO(str.encode(self.fcontent)), self.fname),
                # By setting force False only txt files will be allowed for upload
                # Strange, but it is how the endpoint is configured to improve the tests
                "force": False,
            },
        )
        assert r.status_code == 200

        destination_path = UPLOAD_PATH.joinpath(upload_folder, self.fname)
        assert destination_path.exists()
        assert oct(os.stat(destination_path).st_mode & 0o777) == "0o440"

        r = client.put(
            f"{API_URI}/tests/upload",
            data={"file": (io.BytesIO(str.encode(self.fcontent)), self.fname)},
        )
        assert r.status_code == 400
        err = f"File '{self.fname}' already exists, use force parameter to overwrite"
        assert self.get_content(r) == err

        r = client.put(
            f"{API_URI}/tests/upload",
            data={
                "file": (io.BytesIO(str.encode(self.fcontent)), self.fname),
                "force": True,
            },
        )
        assert r.status_code == 200

        destination_path = UPLOAD_PATH.joinpath(upload_folder, self.fname)
        assert destination_path.exists()
        assert oct(os.stat(destination_path).st_mode & 0o777) == "0o440"

        c = self.get_content(r)
        assert c.get("filename") == self.fname
        meta = c.get("meta")
        assert meta is not None
        assert meta.get("charset") is not None
        assert meta.get("type") is not None

    def test_download(self, client: FlaskClient) -> None:

        self.fname = self.get("fname")
        self.fcontent = self.get("fcontent")
        # as defined in test_upload.py for normal uploads
        upload_folder = "fixsubfolder"

        r = client.get(f"{API_URI}/tests/download/folder/doesnotexist")
        assert r.status_code == 400

        # this is a special case introduced for testing purpose
        # this special file name will be converted to None into the endpoint
        r = client.get(f"{API_URI}/tests/download/folder/SPECIAL-VALUE-FOR-NONE")
        assert r.status_code == 400

        r = client.get(f"{API_URI}/tests/download/{upload_folder}/{self.fname}")
        assert r.status_code == 200
        content = r.data.decode("utf-8")
        assert content == self.fcontent

        new_content = "new content"
        r = client.put(
            f"{API_URI}/tests/upload",
            data={
                "file": (io.BytesIO(str.encode(new_content)), self.fname),
                "force": True,
            },
        )
        assert r.status_code == 200

        r = client.get(f"{API_URI}/tests/download/{upload_folder}/{self.fname}")
        assert r.status_code == 200
        content = r.data.decode("utf-8")
        assert content != self.fcontent
        assert content == new_content

        r = client.get(
            f"{API_URI}/tests/download/{upload_folder}/{self.fname}",
            query_string={"stream": True},
        )
        assert r.status_code == 200
        content = r.data.decode("utf-8")
        assert content == new_content

        r = client.get(
            f"{API_URI}/tests/download/{upload_folder}/doesnotexist",
            query_string={"stream": True},
        )
        assert r.status_code == 400

    def test_chunked(self, client: FlaskClient, faker: Faker) -> None:

        self.fname = self.get("fname")
        self.fcontent = self.get("fcontent")

        # as defined in test_upload.py for chunked uploads
        upload_folder = "fixed"

        r = client.post(f"{API_URI}/tests/chunkedupload", data={"force": True})
        assert r.status_code == 400

        filename = "fixed.filename.txt"
        data = {
            "force": True,
            "name": filename,
            "size": "999",
            "mimeType": "application/zip",
            "lastModified": 1590302749209,
        }
        r = client.post(f"{API_URI}/tests/chunkedupload", data=data)
        assert r.status_code == 201
        assert self.get_content(r) == ""

        with io.StringIO(faker.text()) as f:
            r = client.put(f"{API_URI}/tests/chunkedupload/{filename}", data=f)
        assert r.status_code == 400
        assert self.get_content(r) == "Invalid request"

        with io.StringIO(faker.text()) as f:
            r = client.put(
                f"{API_URI}/tests/chunkedupload/{filename}",
                data=f,
                headers={"Content-Range": "!"},
            )
        assert r.status_code == 400
        assert self.get_content(r) == "Invalid request"

        up_data = faker.pystr(min_chars=24, max_chars=48)
        STR_LEN = len(up_data)
        with io.StringIO(up_data[0:5]) as f:
            r = client.put(
                f"{API_URI}/tests/chunkedupload/{filename}",
                data=f,
                headers={"Content-Range": f"bytes 0-5/{STR_LEN}"},
            )
        assert r.status_code == 206
        assert self.get_content(r) == "partial"

        with io.StringIO(up_data[5:]) as f:
            r = client.put(
                f"{API_URI}/tests/chunkedupload/{filename}",
                data=f,
                headers={"Content-Range": f"bytes 5-{STR_LEN}/{STR_LEN}"},
            )
        assert r.status_code == 200
        c = self.get_content(r)
        assert c.get("filename") is not None
        uploaded_filename = c.get("filename")
        meta = c.get("meta")
        assert meta is not None
        assert meta.get("charset") == "us-ascii"
        assert meta.get("type") == "text/plain"

        destination_path = UPLOAD_PATH.joinpath(upload_folder, filename)
        assert destination_path.exists()
        assert oct(os.stat(destination_path).st_mode & 0o777) == "0o440"

        r = client.get(f"{API_URI}/tests/download/{upload_folder}/{uploaded_filename}")
        assert r.status_code == 200
        content = r.data.decode("utf-8")
        assert content == up_data

        r = client.get(f"{API_URI}/tests/download/{upload_folder}/{uploaded_filename}")
        assert r.status_code == 200
        content = r.data.decode("utf-8")
        assert content == up_data

        r = client.get(
            f"{API_URI}/tests/download/{upload_folder}/{uploaded_filename}",
            headers={"Range": ""},
        )
        assert r.status_code == 416

        r = client.get(
            f"{API_URI}/tests/download/{upload_folder}/{uploaded_filename}",
            headers={"Range": f"0-{STR_LEN - 1}"},
        )
        assert r.status_code == 416

        r = client.get(
            f"{API_URI}/tests/download/{upload_folder}/{uploaded_filename}",
            headers={"Range": "bytes=0-9999999999999999"},
        )

        from werkzeug import __version__ as werkzeug_version

        # Back-compatibility check for B2STAGE
        if werkzeug_version == "0.16.1":  # pragma: no cover
            assert r.status_code == 200
        else:
            assert r.status_code == 206

        r = client.get(
            f"{API_URI}/tests/download/{upload_folder}/{uploaded_filename}",
            headers={"Range": "bytes=0-4"},
        )
        assert r.status_code == 206
        content = r.data.decode("utf-8")
        assert content == up_data[0:5]

        r = client.get(
            f"{API_URI}/tests/download/{upload_folder}/{uploaded_filename}",
            headers={"Range": f"bytes=5-{STR_LEN - 1}"},
        )
        assert r.status_code == 206
        content = r.data.decode("utf-8")
        assert content == up_data[5:]

        r = client.get(
            f"{API_URI}/tests/download/{upload_folder}/{uploaded_filename}",
            headers={"Range": f"bytes=0-{STR_LEN - 1}"},
        )
        # Back-compatibility check for B2STAGE
        if werkzeug_version == "0.16.1":  # pragma: no cover
            assert r.status_code == 200
        else:
            assert r.status_code == 206
        content = r.data.decode("utf-8")
        assert content == up_data

        # Send a new string as content file. Will be appended as prefix
        up_data2 = faker.pystr(min_chars=24, max_chars=48)
        STR_LEN = len(up_data2)
        with io.StringIO(up_data2) as f:
            r = client.put(
                f"{API_URI}/tests/chunkedupload/{filename}",
                data=f,
                headers={"Content-Range": f"bytes */{STR_LEN}"},
            )
        assert r.status_code == 503
        assert self.get_content(r) == "Permission denied: failed to write the file"

        # force the file to be writeable again
        destination_path = UPLOAD_PATH.joinpath(upload_folder, filename)
        # -rw-rw----
        destination_path.chmod(0o660)

        up_data2 = faker.pystr(min_chars=24, max_chars=48)
        STR_LEN = len(up_data2)
        with io.StringIO(up_data2) as f:
            r = client.put(
                f"{API_URI}/tests/chunkedupload/{filename}",
                data=f,
                headers={"Content-Range": f"bytes */{STR_LEN}"},
            )

        assert r.status_code == 200

        destination_path = UPLOAD_PATH.joinpath(upload_folder, filename)
        assert destination_path.exists()
        # File permissions are restored
        assert oct(os.stat(destination_path).st_mode & 0o777) == "0o440"

        # c = self.get_content(r)
        # assert c.get('filename') is not None
        # uploaded_filename = c.get('filename')
        # meta = c.get('meta')
        # assert meta is not None
        # assert meta.get('charset') == 'us-ascii'
        # assert meta.get('type') == 'text/plain'

        # r = client.get(
        #     f'{API_URI}/tests/download/{upload_folder}/{uploaded_filename}'
        # )
        # assert r.status_code == 200
        # content = r.data.decode('utf-8')
        # # Uhmmm... should not be up_data2 + up_data ??
        # assert content == up_data + up_data2

        data["force"] = False
        r = client.post(f"{API_URI}/tests/chunkedupload", data=data)
        assert r.status_code == 400
        err = f"File '{uploaded_filename}' already exists"
        assert self.get_content(r) == err

        data["force"] = True
        r = client.post(f"{API_URI}/tests/chunkedupload", data=data)
        assert r.status_code == 201
        assert self.get_content(r) == ""

        data["name"] = "fixed.filename.notallowed"
        data["force"] = False
        r = client.post(f"{API_URI}/tests/chunkedupload", data=data)
        assert r.status_code == 400
        assert self.get_content(r) == "File extension not allowed"
