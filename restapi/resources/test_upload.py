# -*- coding: utf-8 -*-
# from flask import request
from flask_apispec import MethodResource
from flask_apispec import use_kwargs
from marshmallow import fields
from restapi.rest.definition import EndpointResource
from restapi.services.uploader import Uploader
# from restapi.exceptions import RestApiException
from restapi import decorators
from restapi.confs import TESTING
from restapi.confs import UPLOAD_PATH
from restapi.utilities.logs import log


if TESTING:
    class TestUpload(MethodResource, EndpointResource, Uploader):

        labels = ["tests"]
        # Set an invalid baseuri to test the automatic fallback to /api
        baseuri = "/invalid"

        _PUT = {
            "/tests/upload": {
                "summary": "Execute tests with the uploader",
                "description": "Only enabled in testing mode",
                "responses": {
                    "200": {"description": "Tests executed"},
                },
            },
            "/tests/upload/<chunked>": {
                "summary": "Execute tests with the chunked uploader",
                "description": "Only enabled in testing mode",
                "responses": {
                    "200": {"description": "Tests executed"},
                },
            },
        }
        _POST = {
            "/tests/upload": {
                "summary": "Initialize tests on chunked upload",
                "description": "Only enabled in testing mode",
                "responses": {
                    "200": {"description": "Schema retrieved"},
                    "201": {"description": "Upload initialized"},
                },
            },
        }

        @decorators.catch_errors()
        @use_kwargs({'force': fields.Bool()})
        def put(self, chunked=None, force=False):

            if chunked:
                filename = 'fixed.filename'
                completed, response = self.chunk_upload(UPLOAD_PATH, filename)

                if completed:
                    log.info("Upload completed")

            else:
                response = self.upload(force=force)
            return response

        @decorators.catch_errors()
        @use_kwargs({'force': fields.Bool()})
        def post(self, force=False):

            filename = 'fixed.filename'
            return self.init_chunk_upload(
                UPLOAD_PATH, filename, force=force
            )
