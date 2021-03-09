from pathlib import Path
from typing import Any

from restapi import decorators
from restapi.config import TESTING, UPLOAD_PATH
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
            response = self.upload(subfolder=Path("fixsubfolder"), force=force)
            return response

    class TestChunkedUpload(EndpointResource, Uploader):

        labels = ["tests"]

        @decorators.use_kwargs(Force)
        @decorators.endpoint(
            # forgot the leading slash to test the automatic fix
            path="tests/chunkedupload",
            summary="Execute tests with the chunked uploader",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def put(self, force: bool = False) -> Response:

            filename = "fixed.filename"
            path = UPLOAD_PATH.joinpath("fixed")
            completed, response = self.chunk_upload(path, filename)

            if completed:
                log.info("Upload completed")

            return response

        @decorators.init_chunk_upload
        @decorators.use_kwargs(Force)
        @decorators.endpoint(
            # forgot the leading slash to test the automatic fix
            path="tests/chunkedupload",
            summary="Initialize tests on chunked upload",
            description="Only enabled in testing mode",
            responses={200: "Schema retrieved", 201: "Upload initialized"},
        )
        def post(self, force: bool = False, **kwargs: Any) -> Response:

            # This is just to test the allowed exts without adding a new parameter..
            if not force:
                self.set_allowed_exts(["txt"])

            filename = "fixed.filename"
            path = UPLOAD_PATH.joinpath("fixed")
            return self.init_chunk_upload(path, filename, force=force)
