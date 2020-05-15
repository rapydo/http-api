# -*- coding: utf-8 -*-
from restapi.tests import BaseTests, API_URI


class TestUploadAndDownload(BaseTests):
    @staticmethod
    def test_upload(client):
        endpoint = API_URI + '/tests/upload'
        r = client.get(endpoint)
        assert r.status_codse == 200

    @staticmethod
    def test_download(client):
        endpoint = API_URI + '/tests/download'
        r = client.get(endpoint)
        assert r.status_codse == 200
