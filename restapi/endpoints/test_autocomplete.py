from typing import Dict, List, Tuple

from restapi import decorators
from restapi.config import TESTING
from restapi.models import Schema, fields
from restapi.rest.definition import EndpointResource, Response

if TESTING:

    names = ["oliver", "jack", "harry", "charlie", "thomas"]
    surnames = ["smith", "jones", "taylor", "brown", "williams"]
    nicknames = ["kid", "good", "bad", "ugly", "ripper"]

    class MyElement(Schema):
        my_id = fields.Str(required=True)
        my_label = fields.Str(required=True)

    # This will accept a single element provided by the autocomplete endpoint
    # The frontend is expected to translate this field into an autocomplete field
    class SingleInput(Schema):
        element = fields.Str(
            required=True,
            metadata={
                "autocomplete_endpoint": "/api/tests/autocomplete",
                "autocomplete_id_bind": "my_id",
                "autocomplete_label_bind": "my_label",
                "autocomplete_show_id": False,
            },
        )

    # This will accept a list of elements provided by the autocomplete endpoint.
    # The frontend is expected to translate this field into a multiple autocomplete
    class ListInput(Schema):
        elements = fields.List(
            fields.Str(),
            required=True,
            metadata={
                "autocomplete_endpoint": "/api/tests/autocomplete",
                "autocomplete_id_bind": "my_id",
                "autocomplete_label_bind": "my_label",
                "autocomplete_show_id": True,
            },
        )

    class TestAutocomplete(EndpointResource):
        @staticmethod
        def get_element(name: str, surname: str, nickname: str) -> Tuple[str, str]:
            return (
                f"{name[0].upper()}{surname[0].upper()}{nickname[0].upper()}",
                f"{name.title()} {surname.title()} the {nickname.title()}",
            )

        # This is the autocomplete endpoint
        # It receive a strin an return a list of elements matching the input
        @decorators.marshal_with(MyElement(many=True), code=200)
        @decorators.endpoint(
            path="/tests/autocomplete/<query>",
            summary="Return list of elements matching the input",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self, query: str) -> Response:

            elements: List[Dict[str, str]] = []

            for k1 in names:
                for k2 in surnames:
                    for k3 in nicknames:
                        k, v = self.get_element(k1, k2, k3)

                        if query.lower() in v.lower():
                            elements.append({"my_id": k, "my_label": v})

            return self.response(elements)

        @decorators.use_kwargs(ListInput)
        @decorators.endpoint(
            path="/tests/autocomplete",
            summary="Receives a list of MyElements",
            description="Only enabled in testing mode",
            responses={204: "Tests executed", 400: "Bad Input"},
        )
        def post(self, elements: List[str]) -> Response:

            return self.empty_response()

        @decorators.use_kwargs(SingleInput)
        @decorators.endpoint(
            path="/tests/autocomplete",
            summary="Receives a single MyElement",
            description="Only enabled in testing mode",
            responses={204: "Tests executed", 400: "Bad Input"},
        )
        def put(self, element: str) -> Response:

            return self.empty_response()
