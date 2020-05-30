from flask_apispec import MethodResource

from restapi.rest.definition import EndpointResource

from restapi import decorators
from restapi.confs import TESTING
# from restapi.utilities.logs import log

if TESTING:

    class TestPagination(MethodResource, EndpointResource):

        values = list(range(1, 150))
        _GET = {
            "/tests/pagination": {
                "summary": "Execute tests on a paginated endpoint",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }

        @decorators.catch_errors()
        @decorators.get_pagination
        def get(self, get_total=None, page=None, size=None):

            if get_total:
                return len(TestPagination.values)

            offset = (page - 1) * size
            return TestPagination.values[offset: offset + size]
