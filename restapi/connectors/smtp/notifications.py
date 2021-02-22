import os
from typing import Any, Dict, Optional

from restapi.config import get_project_configuration
from restapi.connectors import smtp
from restapi.services.authentication import User
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


def send_registration_notification(username: str) -> bool:

    return send_email(
        body=f"A new user registered from {username}",
        subject="New user registered",
        to_address=None,
        template="new_user_registered.html",
        data={"username": username},
    )


def send_activation_link(user: User, url: str) -> bool:

    data = {
        "url": url,
        "username": user.email,
        "name": user.name,
        "surname": user.surname,
    }

    return send_email(
        body=f"Follow this link to activate your account: {url}",
        subject=os.getenv("EMAIL_ACTIVATION_SUBJECT", "Account activation"),
        to_address=user.email,
        template="activate_account.html",
        data=data,
    )


def send_password_reset_link(uri: str, reset_email: str) -> bool:

    return send_email(
        body=f"Follow this link to reset your password: {uri}",
        subject="Password Reset",
        to_address=reset_email,
        template="reset_password.html",
        data={"url": uri},
    )


def notify_new_credentials_to_user(user: User, unhashed_password: str) -> bool:

    body = f"""
Username: {user.email}
Password: {unhashed_password}
    """

    return send_email(
        body=body,
        subject="New credentials",
        to_address=user.email,
        template="new_credentials.html",
        data={"username": user.email, "password": unhashed_password},
    )


def notify_update_credentials_to_user(user: User, unhashed_password: str) -> bool:

    body = f"""
Username: {user.email}
Password: {unhashed_password}
    """

    return send_email(
        body=body,
        subject="Password changed",
        to_address=user.email,
        template="update_credentials.html",
        data={"username": user.email, "password": unhashed_password},
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
