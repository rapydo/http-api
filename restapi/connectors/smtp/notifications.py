import os
from typing import Any, Dict, Optional

from restapi.config import get_project_configuration
from restapi.connectors import smtp
from restapi.services.authentication import User
from restapi.utilities.templates import get_html_template


def send_email(
    subject: str,
    body: str,
    to_address: Optional[str] = None,
    template: Optional[str] = None,
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
        subject=subject, body=body, to_address=to_address, plain_body=plain_body
    )


def send_registration_notification(user: User) -> bool:

    return send_email(
        subject="New user registered",
        body=f"A new user registered from {user.email}",
        to_address=None,
        template="new_user_registered.html",
        data=None,
        user=user,
    )


def send_activation_link(user: User, url: str) -> bool:

    return send_email(
        subject=os.getenv("EMAIL_ACTIVATION_SUBJECT", "Account activation"),
        body=f"Follow this link to activate your account: {url}",
        to_address=user.email,
        template="activate_account.html",
        data={"url": url},
        user=user,
    )


def send_password_reset_link(user: User, uri: str, reset_email: str) -> bool:

    return send_email(
        subject="Password Reset",
        body=f"Follow this link to reset your password: {uri}",
        to_address=reset_email,
        template="reset_password.html",
        data={"url": uri},
        user=user,
    )


def notify_new_credentials_to_user(user: User, unhashed_password: str) -> bool:

    body = f"""
Username: {user.email}
Password: {unhashed_password}
    """

    return send_email(
        subject="New credentials",
        body=body,
        to_address=user.email,
        template="new_credentials.html",
        data={"password": unhashed_password},
        user=user,
    )


def notify_update_credentials_to_user(user: User, unhashed_password: str) -> bool:

    body = f"""
Username: {user.email}
Password: {unhashed_password}
    """

    return send_email(
        subject="Password changed",
        body=body,
        to_address=user.email,
        template="update_credentials.html",
        data={"password": unhashed_password},
        user=user,
    )


def send_celery_error_notification(
    task_id: str, task_name: str, arguments: str, error_stack: Any
) -> bool:
    body = f"""
Celery task {task_id} failed

Name: {task_name}

Arguments: {arguments}

Error: {error_stack}
"""

    return send_email(
        subject=f"Task {task_name} failed",
        body=body,
        to_address=None,
        template="celery_error_notification.html",
        data={
            "task_id": task_id,
            "task_name": task_name,
            "arguments": arguments,
            "error_stack": error_stack,
        },
        user=None,
    )
