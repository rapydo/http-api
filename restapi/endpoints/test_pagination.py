from typing import Optional

from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource, Response

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
            self,
            get_total: bool,
            page: int,
            size: int,
            sort_by: Optional[str],
            sort_order: Optional[str],
            input_filter: Optional[str],
        ) -> Response:
            if get_total:
                return self.response(len(TestPagination.values))

            offset = (page - 1) * size
            return self.response(TestPagination.values[offset : offset + size])

        @decorators.get_pagination
        @decorators.endpoint(
            path="/tests/pagination",
            summary="Execute tests on a paginated endpoint",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def post(
            self,
            get_total: bool,
            page: int,
            size: int,
            sort_by: Optional[str],
            sort_order: Optional[str],
            input_filter: Optional[str],
        ) -> Response:
            if get_total:
                return self.response(len(TestPagination.values))

            offset = (page - 1) * size
            return self.response(TestPagination.values[offset : offset + size])
