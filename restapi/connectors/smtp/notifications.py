import os
from typing import Any, Dict, Optional

from restapi.config import get_project_configuration
from restapi.connectors import smtp
from restapi.services.authentication import User
from restapi.utilities.logs import log
from restapi.utilities.templates import get_html_template


def send_email(
    subject: str,
    template: str,
    # if None will be sent to the administrator
    to_address: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
    user: Optional[User] = None,
) -> bool:

    title = get_project_configuration("project.title", default="Unkown title")

    if data is None:
        data = {}

    data.setdefault("project", title)

    if user:
        data.setdefault("username", user.email)
        data.setdefault("name", user.name)
        data.setdefault("surname", user.surname)

    html_body, plain_body = get_html_template(template, data)

    if not html_body:  # pragma: no cover
        log.error("Can't load {}", template)
        return False

    subject = f"{title}: {subject}"
    smtp_client = smtp.get_instance()
    return smtp_client.send(
        subject=subject, body=html_body, to_address=to_address, plain_body=plain_body
    )


def send_registration_notification(user: User) -> bool:

    return send_email(
        subject="New user registered",
        template="new_user_registered.html",
        to_address=None,
        data=None,
        user=user,
    )


def send_activation_link(user: User, url: str) -> bool:

    return send_email(
        subject=os.getenv("EMAIL_ACTIVATION_SUBJECT", "Account activation"),
        template="activate_account.html",
        to_address=user.email,
        data={"url": url},
        user=user,
    )


def send_password_reset_link(user: User, uri: str, reset_email: str) -> bool:

    return send_email(
        subject="Password Reset",
        template="reset_password.html",
        to_address=reset_email,
        data={"url": uri},
        user=user,
    )


def notify_new_credentials_to_user(user: User, unhashed_password: str) -> bool:

    return send_email(
        subject="New credentials",
        template="new_credentials.html",
        to_address=user.email,
        data={"password": unhashed_password},
        user=user,
    )


def notify_update_credentials_to_user(user: User, unhashed_password: str) -> bool:

    return send_email(
        subject="Password changed",
        template="update_credentials.html",
        to_address=user.email,
        data={"password": unhashed_password},
        user=user,
    )


def send_celery_error_notification(
    task_id: str, task_name: str, arguments: str, error_stack: Any
) -> bool:

    return send_email(
        subject=f"Task {task_name} failed",
        template="celery_error_notification.html",
        to_address=None,
        data={
            "task_id": task_id,
            "task_name": task_name,
            "arguments": arguments,
            "error_stack": error_stack,
        },
        user=None,
    )
