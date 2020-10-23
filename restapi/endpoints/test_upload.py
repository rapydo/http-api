from restapi import decorators
from restapi.confs import TESTING, UPLOAD_PATH
from restapi.models import PartialSchema, fields
from restapi.rest.definition import EndpointResource
from restapi.services.uploader import Uploader
from restapi.utilities.logs import log

if TESTING:

    class Force(PartialSchema):
        force = fields.Bool()

    class TestUpload(EndpointResource, Uploader):

        labels = ["tests"]
        # Set an invalid baseuri to test the automatic fallback to /api
        baseuri = "/invalid"

        @decorators.use_kwargs(Force)
        @decorators.endpoint(
            path="/tests/upload",
            summary="Execute tests with the uploader",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        @decorators.endpoint(
            path="/tests/upload/<chunked>",
            summary="Execute tests with the chunked uploader",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def put(self, chunked=None, force=False):

            if chunked:
                filename = "fixed.filename"
                completed, response = self.chunk_upload(UPLOAD_PATH, filename)

                if completed:
                    log.info("Upload completed")

            else:
                # This is just to test the allowed exts without adding a new parameter..
                if not force:
                    self.set_allowed_exts(["txt"])
                response = self.upload(force=force)
            return response

        @decorators.init_chunk_upload
        @decorators.use_kwargs(Force)
        @decorators.endpoint(
            path="/tests/upload",
            summary="Initialize tests on chunked upload",
            description="Only enabled in testing mode",
            responses={200: "Schema retrieved", 201: "Upload initialized"},
        )
        def post(self, force=False, **kwargs):

            filename = "fixed.filename"
            return self.init_chunk_upload(UPLOAD_PATH, filename, force=force)
