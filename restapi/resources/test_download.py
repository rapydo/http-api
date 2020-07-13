from restapi import decorators
from restapi.confs import TESTING, UPLOAD_PATH
from restapi.models import fields
from restapi.rest.definition import EndpointResource
from restapi.services.download import Downloader
from restapi.services.uploader import Uploader

if TESTING:

    class TestDownload(EndpointResource):

        labels = ["tests"]
        # Set an invalid baseuri to test the automatic fallback to /api
        baseuri = "/invalid"

        _GET = {
            "/tests/download": {
                "summary": "Test missing filename",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
            "/tests/download/<fname>": {
                "summary": "Execute tests with the downloader",
                "description": "Only enabled in testing mode",
                "responses": {
                    "200": {"description": "Tests executed"},
                    "206": {"description": "Sent partial content"},
                    "416": {"description": "Range Not Satisfiable"},
                },
            },
        }

        @decorators.use_kwargs({"stream": fields.Bool()}, locations=["query"])
        def get(self, fname=None, stream=False):

            if stream:
                fpath = Uploader.absolute_upload_file(fname, subfolder=UPLOAD_PATH)
                return Downloader.send_file_streamed(fpath)

            return Downloader.download(fname)
