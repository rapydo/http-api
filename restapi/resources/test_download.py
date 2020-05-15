# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from restapi.rest.definition import EndpointResource
from restapi.services.download import Downloader
# from restapi.exceptions import RestApiException
from restapi import decorators
from restapi.confs import TESTING


if TESTING:
    class TestDownload(MethodResource, EndpointResource, Downloader):

        labels = ["tests"]

        _GET = {
            "/download": {
                "summary": "Execute tests with the downloader",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }

        @decorators.catch_errors()
        def get(self, test):
            return 1
