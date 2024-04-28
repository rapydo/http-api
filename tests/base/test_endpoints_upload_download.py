import io
import os
import warnings

from faker import Faker

from restapi.config import DATA_PATH, PRODUCTION, get_backend_url
from restapi.tests import API_URI, SERVER_URI, BaseTests, FlaskClient


def get_location_header(headers: dict[str, str], expected: str) -> str:
    assert "Location" in headers
    location = headers["Location"]

    if PRODUCTION:
        assert location.startswith("https://")

    host = get_backend_url()
    assert location.startswith(host)
    location = location.replace(host, SERVER_URI)
    assert location == expected
    return location


class TestUploadAndDownload(BaseTests):
    def test_simple_upload_and_download(
        self, client: FlaskClient, faker: Faker
    ) -> None:
        warnings.filterwarnings(
            "ignore", message="unclosed file <_io.BufferedReader name="
        )
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

        destination_path = DATA_PATH.joinpath(upload_folder, self.fname)
        assert destination_path.exists()
        assert oct(os.stat(destination_path).st_mode & 0o777) == "0o440"

        r = client.put(
            f"{API_URI}/tests/upload",
            data={"file": (io.BytesIO(str.encode(self.fcontent)), self.fname)},
        )
        assert r.status_code == 409
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

        destination_path = DATA_PATH.joinpath(upload_folder, self.fname)
        assert destination_path.exists()
        assert oct(os.stat(destination_path).st_mode & 0o777) == "0o440"

        c = self.get_content(r)
        assert isinstance(c, dict)
        assert c.get("filename") == self.fname
        meta = c.get("meta")
        assert meta is not None
        assert meta.get("charset") is not None
        assert meta.get("type") is not None

        self.fname = self.get("fname")
        self.fcontent = self.get("fcontent")
        # as defined in test_upload.py for normal uploads
        upload_folder = "fixsubfolder"

        r = client.get(f"{API_URI}/tests/download/folder/doesnotexist")
        assert r.status_code == 404
        assert self.get_content(r) == "The requested file does not exist"

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
        assert r.status_code == 404

    def test_chunked_upload_and_download(
        self, client: FlaskClient, faker: Faker
    ) -> None:
        warnings.filterwarnings(
            "ignore", message="unclosed file <_io.BufferedReader name="
        )

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
        upload_endpoint = get_location_header(
            r.headers, expected=f"{API_URI}/tests/chunkedupload/{filename}"
        )

        data["force"] = False
        r = client.post(f"{API_URI}/tests/chunkedupload", data=data)
        assert r.status_code == 409
        assert self.get_content(r) == f"File '{filename}' already exists"

        with io.StringIO(faker.text()) as f:
            r = client.put(upload_endpoint, data=f)
        assert r.status_code == 400
        assert self.get_content(r) == "Invalid request"

        with io.StringIO(faker.text()) as f:
            r = client.put(
                upload_endpoint,
                data=f,
                headers={"Content-Range": "!"},
            )
        assert r.status_code == 400
        assert self.get_content(r) == "Invalid request"

        up_data = faker.pystr(min_chars=24, max_chars=48).lower()
        STR_LEN = len(up_data)
        with io.StringIO(up_data[0:5]) as f:
            r = client.put(
                upload_endpoint,
                data=f,
                headers={"Content-Range": f"bytes 0-5/{STR_LEN}"},
            )
        assert r.status_code == 206
        assert self.get_content(r) == "partial"

        destination_path = DATA_PATH.joinpath(upload_folder, filename)
        assert destination_path.exists()
        # The file is still writeable because the upload is in progress
        assert oct(os.stat(destination_path).st_mode & 0o777) != "0o440"

        with io.StringIO(up_data[5:]) as f:
            r = client.put(
                upload_endpoint,
                data=f,
                headers={"Content-Range": f"bytes 5-{STR_LEN}/{STR_LEN}"},
            )
        assert r.status_code == 200
        c = self.get_content(r)
        assert isinstance(c, dict)
        assert c.get("filename") is not None
        uploaded_filename = c.get("filename")
        meta = c.get("meta")
        assert meta is not None
        assert meta.get("charset") == "us-ascii"
        assert meta.get("type") == "text/plain"

        destination_path = DATA_PATH.joinpath(upload_folder, filename)
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
        assert r.status_code == 206
        content = r.data.decode("utf-8")
        assert content == up_data

        # Send a new string as content file. Will be appended as prefix
        up_data2 = faker.pystr(min_chars=24, max_chars=48)
        STR_LEN = len(up_data2)
        with io.StringIO(up_data2) as f:
            r = client.put(
                upload_endpoint,
                data=f,
                headers={"Content-Range": f"bytes */{STR_LEN}"},
            )
        assert r.status_code == 503
        assert self.get_content(r) == "Permission denied: failed to write the file"

        # force the file to be writeable again
        destination_path = DATA_PATH.joinpath(upload_folder, filename)
        # -rw-rw----
        destination_path.chmod(0o660)

        with io.StringIO(up_data2) as f:
            r = client.put(
                upload_endpoint,
                data=f,
                headers={"Content-Range": f"bytes */{STR_LEN}"},
            )

        assert r.status_code == 200

        destination_path = DATA_PATH.joinpath(upload_folder, filename)
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
        assert r.status_code == 409
        err = f"File '{uploaded_filename}' already exists"
        assert self.get_content(r) == err

        data["force"] = True
        r = client.post(f"{API_URI}/tests/chunkedupload", data=data)
        assert r.status_code == 201
        assert self.get_content(r) == ""
        upload_endpoint = get_location_header(
            r.headers, expected=f"{API_URI}/tests/chunkedupload/{filename}"
        )

        data["name"] = "fixed.filename.notallowed"
        data["force"] = False
        r = client.post(f"{API_URI}/tests/chunkedupload", data=data)
        assert r.status_code == 400
        assert self.get_content(r) == "File extension not allowed"

        # Send an upload on a file endpoint not previously initialized
        filename = f"{faker.pystr()}.txt"
        with io.StringIO(up_data2) as f:
            r = client.put(
                f"{API_URI}/tests/chunkedupload/{filename}",
                data=f,
                headers={"Content-Range": f"bytes */{STR_LEN}"},
            )

        assert r.status_code == 503
        error = "Permission denied: the destination file does not exist"
        assert self.get_content(r) == error

        destination_path = DATA_PATH.joinpath(upload_folder, filename)
        assert not destination_path.exists()
