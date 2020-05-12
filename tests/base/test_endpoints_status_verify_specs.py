# -*- coding: utf-8 -*-
from restapi.tests import BaseTests, API_URI, AUTH_URI
from restapi.services.detect import detector
from restapi.utilities.logs import log


class TestApp(BaseTests):

    def test_GET_status(self, client):
        """ Test that the flask server is running and reachable """

        # Check success
        endpoint = API_URI + '/status'
        alive_message = "Server is alive"

        log.info("*** VERIFY if API is online")
        r = client.get(endpoint)
        assert r.status_code == 200
        output = self.get_content(r)
        assert output == alive_message

        # Check failure
        log.info("*** VERIFY if invalid endpoint gives Not Found")
        r = client.get(API_URI)
        assert r.status_code == 404

        # Check HTML response to status if agent/request is text/html
        headers = {"Accept": 'text/html'}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == 200
        output = r.data.decode('utf-8')
        assert output != alive_message
        assert alive_message in output
        assert "<html" in output
        assert "<body>" in output

        # Check /auth/status with no token or invalid token
        r = client.get(AUTH_URI + '/status')
        assert r.status_code == 401

        r = client.get(AUTH_URI + '/status', headers={'Authorization': 'Bearer ABC'})
        assert r.status_code == 401

    def test_GET_specifications(self, client):
        """ Test that the flask server expose swagger specs """

        specs = self.get_specs(client)

        assert "basePath" in specs
        assert "consumes" in specs
        assert "produces" in specs
        assert "application/json" in specs["consumes"]
        assert "application/json" in specs["produces"]
        assert "definitions" in specs
        assert "host" in specs
        assert "info" in specs
        assert "schemes" in specs
        assert "swagger" in specs
        assert "tags" in specs
        assert "security" in specs
        assert "Bearer" in specs["security"][0]
        assert "securityDefinitions" in specs
        assert "Bearer" in specs["securityDefinitions"]
        assert "paths" in specs
        assert "/auth/login" in specs["paths"]
        assert "get" not in specs["paths"]["/auth/login"]
        assert "post" in specs["paths"]["/auth/login"]
        assert "put" not in specs["paths"]["/auth/login"]
        assert "delete" not in specs["paths"]["/auth/login"]

    def test_GET_verify(self, client):

        r = client.get(API_URI + '/status/x')
        assert r.status_code == 401

        headers, _ = self.do_login(client, None, None)

        r = client.get(API_URI + '/status/x', headers=headers)
        assert r.status_code == 404

        # not important to test all of them... just test some service that are expected
        # to be enabled and othersthat are disabled
        services = ['neo4j', 'sqlalchemy', 'mongo', 'rabbit']
        for service in services:

            r = client.get(API_URI + '/status/' + service, headers=headers)
            if detector.check_availability(service):
                assert r.status_code == 200
            else:
                assert r.status_code == 404
