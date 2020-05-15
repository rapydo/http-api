# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from restapi.rest.definition import EndpointResource
from restapi.services.uploader import Uploader
# from restapi.exceptions import RestApiException
from restapi import decorators
from restapi.confs import TESTING


if TESTING:
    class TestUpload(MethodResource, EndpointResource, Uploader):

        labels = ["tests"]

        _GET = {
            "/tests/upload": {
                "summary": "Execute tests with the uploader",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }

        @decorators.catch_errors()
        def get(self, test):
            return 1
