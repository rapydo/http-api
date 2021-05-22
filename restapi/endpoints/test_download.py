from pathlib import Path

from restapi import decorators
from restapi.config import TESTING
from restapi.models import fields
from restapi.rest.definition import EndpointResource, Response
from restapi.services.download import Downloader
from restapi.services.uploader import Uploader

if TESTING:

    class TestDownload(EndpointResource):

        labels = ["tests"]

        @decorators.use_kwargs({"stream": fields.Bool()}, location="query")
        @decorators.endpoint(
            # forgot the leading slash to test the automatic fix
            path="tests/download/<folder>/<fname>",
            summary="Execute tests with the downloader",
            description="Only enabled in testing mode",
            responses={
                200: "Tests executed",
                206: "Sent partial content",
                404: "The requested file does not exist",
                416: "Range Not Satisfiable",
            },
        )
        def get(self, folder: str, fname: str, stream: bool = False) -> Response:
            if stream:
                fpath = Uploader.absolute_upload_file(
                    fname,
                    # The same defined in test_upload
                    subfolder=Path(folder),
                )
                return Downloader.send_file_streamed(fpath)

            if fname == "SPECIAL-VALUE-FOR-NONE":
                return Downloader.download(None)

            return Downloader.download(fname, subfolder=Path(folder))
