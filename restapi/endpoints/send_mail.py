from typing import List, Optional

from restapi import decorators
from restapi.connectors import smtp
from restapi.endpoints.schemas import MailInput
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Role

# from restapi.utilities.logs import log


class SendMail(EndpointResource):

    # depends_on = [""]
    labels = ["admin"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(MailInput)
    @decorators.endpoint(
        path="/admin/mail",
        summary="Send mail messages",
        responses={200: "Mail successfully sent"},
    )
    def post(
        self,
        subject: str,
        body: str,
        to: str,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
    ) -> Response:

        smtp_client = smtp.get_instance()

        # It should use a generic html template... to be added
        # after implemeted header and footer html templates

        smtp_client.send(
            body=body,
            subject=subject,
            to_address=to,
            from_address=None,
            cc=cc,
            bcc=bcc,
            plain_body=None,
        )
        return self.empty_response()
