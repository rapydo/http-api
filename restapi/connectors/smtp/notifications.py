import os
from typing import Any, Dict, Optional

from restapi.config import get_project_configuration
from restapi.connectors import smtp
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.templates import get_html_template


def send_email(
    body: str,
    subject: str,
    to_address: Optional[str] = None,
    template: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
) -> bool:

    title = get_project_configuration("project.title", default="Unkown title")

    html_body = None
    plain_body = None

    if template:
        html_body = get_html_template(template, data)

    if html_body:
        plain_body = body
        body = html_body

    subject = f"{title}: {subject}"
    smtp_client = smtp.get_instance()
    return smtp_client.send(
        body=body, subject=subject, to_address=to_address, plain_body=plain_body
    )


def send_registration_notification(username: str) -> None:

    send_email(
        body=f"New credentials request from {username}",
        subject="New credentials requested",
        to_address=None,
        template="new_credentials_notification.html",
        data={"username": username},
    )


def send_activation_link(user, url):

    data = {
        "url": url,
        "username": user.email,
        "name": user.name,
        "surname": user.surname,
    }

    sent = send_email(
        body=f"Follow this link to activate your account: {url}",
        subject=os.getenv("EMAIL_ACTIVATION_SUBJECT", "Account activation"),
        to_address=user.email,
        template="activate_account.html",
        data=data,
    )

    if not sent:  # pragma: no cover
        raise ServiceUnavailable("Error sending email, please retry")


def send_password_reset_link(uri: str, reset_email: str) -> None:

    sent = send_email(
        body=f"Follow this link to reset your password: {uri}",
        subject="Password Reset",
        to_address=reset_email,
        template="reset_password.html",
        data={"url": uri},
    )

    if not sent:  # pragma: no cover
        raise ServiceUnavailable("Error sending email, please retry")


def notify_password_to_userf(user, unhashed_password, is_update=False):

    if is_update:
        subject = "Password changed"
        template = "update_credentials.html"
    else:
        subject = "New credentials"
        template = "new_credentials.html"

    body = f"""
Username: {user.email}
Password: {unhashed_password}
    """

    send_email(
        body=body,
        subject=subject,
        to_address=user.email,
        template=template,
        data={"username": user.email, "password": unhashed_password},
    )


def send_celery_error_notification(
    task_id: str, task_name: str, arguments: str, error_stack: Any
) -> None:
    body = f"""
Celery task {task_id} failed

Name: {task_name}

Arguments: {arguments}

Error: {error_stack}
"""

    send_email(
        body=body,
        subject=f"Task {task_name} failed",
        to_address=None,
        template="celery_error_notification.html",
        data={
            "task_id": task_id,
            "task_name": task_name,
            "arguments": arguments,
            "error_stack": error_stack,
        },
    )
