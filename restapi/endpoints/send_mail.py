from typing import Any, Dict, List, Optional

from restapi import decorators
from restapi.connectors import smtp
from restapi.connectors.smtp.notifications import _get_html_template, convert_html2text
from restapi.endpoints.schemas import MailInput, MailOutput
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Role
from restapi.utilities.logs import log


class SendMail(EndpointResource):

    # depends_on = [""]
    labels = ["admin"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(MailInput)
    @decorators.marshal_with(MailOutput)
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
        dry_run: bool = False,
    ) -> Response:

        replaces: Dict[str, Any] = {}

        header_html, header_plain = _get_html_template("email_header.html", replaces)
        footer_html, footer_plain = _get_html_template("email_footer.html", replaces)

        body = body.replace("\n", "<br/>")

        html_body = f"{header_html}{body}{footer_html}"
        plain_body = f"{header_plain}{convert_html2text(body)}{footer_html}"

        if dry_run:
            return self.response(
                {
                    "html_body": html_body,
                    "plain_body": plain_body,
                    "subject": subject,
                    "to": to,
                    "cc": cc,
                    "bcc": bcc,
                }
            )
        else:
            smtp_client = smtp.get_instance()
            smtp_client.send(
                body=html_body,
                subject=subject,
                to_address=to,
                from_address=None,
                cc=cc,
                bcc=bcc,
                plain_body=plain_body,
            )
        return self.empty_response()
