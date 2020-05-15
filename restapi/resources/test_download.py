# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from flask_apispec import use_kwargs
from marshmallow import fields
from restapi.models import Schema
from restapi.rest.definition import EndpointResource
from restapi.services.download import Downloader
from restapi.services.uploader import Uploader
# from restapi.exceptions import RestApiException
from restapi import decorators
from restapi.confs import UPLOAD_PATH
from restapi.confs import TESTING


if TESTING:

    class Input(Schema):

        stream = fields.Bool()
        partial = fields.Bool()

    class TestDownload(MethodResource, EndpointResource, Downloader):

        labels = ["tests"]

        _GET = {
            "/tests/download": {
                "summary": "Test missing filename",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
            "/tests/download/<fname>": {
                "summary": "Execute tests with the downloader",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }

        @decorators.catch_errors()
        @use_kwargs(Input, locations=['query'])
        def get(self, fname=None, **kwargs):

            stream = kwargs.get('stream', False)
            partial = kwargs.get('partial', False)

            if stream:
                fpath = Uploader.absolute_upload_file(fname, subfolder=UPLOAD_PATH)
                return self.send_file_streamed(fpath)

            if partial:
                fpath = Uploader.absolute_upload_file(fname, subfolder=UPLOAD_PATH)
                return self.send_file_partial(fpath)

            return self.download(fname)
