import gzip
from io import BytesIO

from restapi.tests import API_URI, BaseTests, FlaskClient


class TestApp(BaseTests):
    def test_encoding(self, client: FlaskClient) -> None:
        """Test that the flask server is running and reachable"""

        # Check success
        alive_message = "Server is alive"

        # Verify default is not HTML
        r = client.get(f"{API_URI}/status")
        assert r.status_code == 200
        response = self.get_content(r)
        assert response == alive_message

        # Check HTML response if agent/request is text/html
        headers = {"Accept": "text/html"}
        r = client.get(f"{API_URI}/status", headers=headers)
        assert r.status_code == 200
        output = r.data.decode("utf-8")
        assert output != alive_message
        assert alive_message in output
        assert "<html" in output
        assert "<body>" in output

        # HTML response are only enabled for few endpoints
        r = client.get(f"{API_URI}/tests/gzip/1", headers=headers)
        assert r.status_code == 200
        output = r.data.decode("utf-8")
        assert "<html" not in output

        # Verify gzip encoding
        headers = {"Accept-Encoding": "gzip"}
        r = client.get(f"{API_URI}/status", headers=headers)
        assert r.status_code == 200
        # gzip compression is not enabled for small contents
        assert r.headers.get("Content-Encoding") != "gzip"

        r = client.get(f"{API_URI}/tests/gzip/0", headers=headers)
        assert r.status_code == 416
        # gzip compression is not enabled for error responses
        assert r.headers.get("Content-Encoding") != "gzip"

        r = client.get(f"{API_URI}/tests/gzip/1", headers=headers)
        assert r.status_code == 200
        # gzip compression is not enabled for small contents
        assert r.headers.get("Content-Encoding") != "gzip"

        # This will return a long string of 1000 aaaaaaaaaaaaaaaaaaaa
        r = client.get(f"{API_URI}/tests/gzip/1000", headers=headers)
        assert r.status_code == 200
        # A string with len 1000 is about 1 kb, still too small to enable gzip encoding
        assert r.headers.get("Content-Encoding") != "gzip"

        # This will return a long string of 2000 aaaaaaaaaaaaaaa
        r = client.get(f"{API_URI}/tests/gzip/2000")
        assert r.status_code == 200
        assert r.headers.get("Content-Encoding") != "gzip"
        uncompressed_output = r.data.decode("utf-8")
        assert r.headers.get("Content-Length") == str(len(uncompressed_output))

        # This will return a long gzipped string of 2000 aaaaaaaaaaaaaaa
        r = client.get(f"{API_URI}/tests/gzip/2000", headers=headers)
        assert r.status_code == 200
        assert r.headers.get("Content-Encoding") == "gzip"
        gzipped_output = r.data

        assert r.headers.get("Content-Length") == str(len(gzipped_output))

        assert len(gzipped_output) < len(uncompressed_output)

        content = gzip.GzipFile(fileobj=BytesIO(gzipped_output)).read()

        assert len(content) == len(uncompressed_output)
        assert content.decode("utf-8") == uncompressed_output
