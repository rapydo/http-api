from restapi import decorators
from restapi.config import DATA_PATH, TESTING
from restapi.models import fields
from restapi.rest.definition import EndpointResource, Response
from restapi.services.download import Downloader

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
                403: "Invalid file path",
                404: "The requested file does not exist",
                416: "Range Not Satisfiable",
            },
        )
        def get(self, folder: str, fname: str, stream: bool = False) -> Response:
            # The same as defined in test_upload
            subfolder = DATA_PATH.joinpath(folder)

            if stream:
                return Downloader.send_file_streamed(fname, subfolder=subfolder)

            return Downloader.send_file_content(fname, subfolder=subfolder)
