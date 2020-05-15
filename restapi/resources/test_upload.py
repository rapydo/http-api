# -*- coding: utf-8 -*-
# from flask import request
from flask_apispec import MethodResource
from flask_apispec import use_kwargs
from restapi.rest.definition import EndpointResource
from restapi.services.uploader import Uploader
# from restapi.exceptions import RestApiException
from restapi import decorators
from restapi.confs import TESTING
from restapi.models import Schema
from marshmallow import fields
# from restapi.utilities.logs import log

class Input(Schema):

    force = fields.Bool()


if TESTING:
    class TestUpload(MethodResource, EndpointResource, Uploader):

        labels = ["tests"]

        _PUT = {
            "/tests/upload": {
                "summary": "Execute tests with the uploader",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }

        @decorators.catch_errors()
        @use_kwargs(Input)
        def put(self, **kwargs):

            force = kwargs.get('force', False)
            # if request.mimetype != 'application/octet-stream':

            # Read the request
            # request.get_data()

            # response = self.upload(subfolder=r.username, force=force)
            response = self.upload(force=force)
            return response
