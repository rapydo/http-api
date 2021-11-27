from restapi import decorators
from restapi.config import TESTING, DATA_PATH
from restapi.models import PartialSchema, fields
from restapi.rest.definition import EndpointResource, Response
from restapi.services.uploader import Uploader
from restapi.utilities.logs import log

if TESTING:

    class Force(PartialSchema):
        force = fields.Bool()

    class TestUpload(EndpointResource, Uploader):

        labels = ["tests"]

        @decorators.use_kwargs(Force)
        @decorators.endpoint(
            # forget the leading slash to test the automatic fix
            path="tests/upload",
            summary="Execute tests with the uploader",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def put(self, force: bool = False) -> Response:

            # This is just to test the allowed exts without adding a new parameter..
            if not force:
                self.set_allowed_exts(["txt"])
            response = self.upload(
                subfolder=DATA_PATH.joinpath("fixsubfolder"), force=force
            )
            return response

    class TestChunkedUpload(EndpointResource, Uploader):

        labels = ["tests"]

        @decorators.init_chunk_upload
        @decorators.use_kwargs(Force)
        @decorators.endpoint(
            # forgot the leading slash to test the automatic fix
            path="tests/chunkedupload",
            summary="Initialize tests on chunked upload",
            description="Only enabled in testing mode",
            responses={200: "Schema retrieved", 201: "Upload initialized"},
        )
        def post(
            self,
            name: str,
            mimeType: str,
            size: int,
            lastModified: int,
            force: bool = False,
        ) -> Response:

            # This is just to test the allowed exts without adding a new parameter..
            if not force:
                self.set_allowed_exts(["txt"])

            path = DATA_PATH.joinpath("fixed")
            return self.init_chunk_upload(path, name, force=force)

        @decorators.use_kwargs(Force)
        @decorators.endpoint(
            # forgot the leading slash to test the automatic fix
            path="tests/chunkedupload/<filename>",
            summary="Execute tests with the chunked uploader",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def put(self, filename: str, force: bool = False) -> Response:

            path = DATA_PATH.joinpath("fixed")
            completed, response = self.chunk_upload(path, filename)

            if completed:
                log.info("Upload completed")

            return response
