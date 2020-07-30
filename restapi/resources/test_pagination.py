from restapi import decorators
from restapi.confs import TESTING
from restapi.rest.definition import EndpointResource

if TESTING:

    class TestPagination(EndpointResource):

        # 150 integers from 1 to 150
        values = list(range(1, 151))
        _GET = {
            "/tests/pagination": {
                "summary": "Execute tests on a paginated endpoint",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }
        _POST = {
            "/tests/pagination": {
                "summary": "Execute tests on a paginated endpoint",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }

        @decorators.get_pagination
        def get(self, get_total, page, size):
            return self.endpoint(get_total, page, size)

        @decorators.get_pagination
        def post(self, get_total, page, size):
            return self.endpoint(get_total, page, size)

        def endpoint(self, get_total, page, size):

            if get_total:
                return len(TestPagination.values)

            offset = (page - 1) * size
            return TestPagination.values[offset : offset + size]
