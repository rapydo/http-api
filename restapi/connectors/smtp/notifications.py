import os
from typing import Any, Optional

from restapi.config import get_frontend_url, get_project_configuration
from restapi.connectors import Connector, smtp
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log
from restapi.utilities.templates import get_html_template


def send_registration_notification(username: str) -> None:
    title = get_project_configuration("project.title", default="Unkown title")
    subject = f"{title} New credentials requested"
    body = f"New credentials request from {username}"

    smtp_client = smtp.get_instance()
    smtp_client.send(body, subject)


def send_activation_link(user):

    auth = Connector.get_authentication_instance()
    title = get_project_configuration("project.title", default="Unkown title")

    activation_token, payload = auth.create_temporary_token(user, auth.ACTIVATE_ACCOUNT)

    server_url = get_frontend_url()

    rt = activation_token.replace(".", "+")
    log.debug("Activation token: {}", rt)
    url = f"{server_url}/public/register/{rt}"
    body: Optional[str] = f"Follow this link to activate your account: {url}"

    # customized template
    template_file = "activate_account.html"
    html_body = get_html_template(
        template_file,
        {
            "url": url,
            "username": user.email,
            "name": user.name,
            "surname": user.surname,
        },
    )
    if html_body is None:
        html_body = body
        body = None

    default_subject = f"{title} account activation"
    subject = os.getenv("EMAIL_ACTIVATION_SUBJECT", default_subject)

    smtp_client = smtp.get_instance()
    sent = smtp_client.send(html_body, subject, user.email, plain_body=body)
    if not sent:  # pragma: no cover
        raise ServiceUnavailable("Error sending email, please retry")

    auth.save_token(user, activation_token, payload, token_type=auth.ACTIVATE_ACCOUNT)


def send_password_reset_link(uri, title, reset_email):
    # Internal templating
    body: Optional[str] = f"Follow this link to reset your password: {uri}"
    html_body = get_html_template("reset_password.html", {"url": uri})
    if html_body is None:
        log.warning("Unable to find email template")
        html_body = body
        body = None
    subject = f"{title} Password Reset"

    smtp_client = smtp.get_instance()

    c = smtp_client.send(html_body, subject, reset_email, plain_body=body)
    # it cannot fail during tests, because the email sending is mocked
    if not c:  # pragma: no cover
        raise ServiceUnavailable("Error sending email, please retry")


def notify_password_to_userf(user, unhashed_password, is_update=False):

    title = get_project_configuration("project.title", default="Unkown title")

    if is_update:
        subject = f"{title}: password changed"
        template = "update_credentials.html"
    else:
        subject = f"{title}: new credentials"
        template = "new_credentials.html"

    replaces = {"username": user.email, "password": unhashed_password}

    html = get_html_template(template, replaces)

    body = f"""
Username: {user.email}
Password: {unhashed_password}
    """

    smtp_client = smtp.get_instance()
    if html is None:
        smtp_client.send(body, subject, user.email)
    else:
        smtp_client.send(html, subject, user.email, plain_body=body)


def send_celery_error_notification(
    task_id: str, task_name: str, arguments: str, error_stack: Any
) -> None:
    body = f"""
Celery task {task_id} failed

Name: {task_name}

Arguments: {arguments}

Error: {error_stack}
"""

    project = get_project_configuration(
        "project.title",
        default="Unkown title",
    )
    subject = f"{project}: task {task_name} failed"

    smtp_client = smtp.get_instance()
    smtp_client.send(body, subject)
