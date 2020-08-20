from restapi import decorators
from restapi.confs import TESTING
from restapi.rest.definition import EndpointResource

if TESTING:

    class TestPagination(EndpointResource):

        # 150 integers from 1 to 150
        values = list(range(1, 151))

        @decorators.get_pagination
        @decorators.endpoint(
            path="/tests/pagination",
            summary="Execute tests on a paginated endpoint",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(
            self, get_total, page, size, sort_by, sort_order, input_filter,
        ):
            if get_total:
                return len(TestPagination.values)

            offset = (page - 1) * size
            return TestPagination.values[offset : offset + size]

        @decorators.get_pagination
        @decorators.endpoint(
            path="/tests/pagination",
            summary="Execute tests on a paginated endpoint",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def post(
            self, get_total, page, size, sort_by, sort_order, input_filter,
        ):
            if get_total:
                return len(TestPagination.values)

            offset = (page - 1) * size
            return TestPagination.values[offset : offset + size]
