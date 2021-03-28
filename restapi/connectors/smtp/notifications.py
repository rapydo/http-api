import os
from typing import Any, Dict, Iterator, Optional, Tuple

import html2text
import jinja2

from restapi.config import (
    ABS_RESTAPI_PATH,
    CUSTOM_PACKAGE,
    MODELS_DIR,
    get_project_configuration,
)
from restapi.connectors import CONNECTORS_FOLDER, Connector, smtp
from restapi.services.authentication import FailedLogin, User
from restapi.utilities.logs import log
from restapi.utilities.time import seconds_to_human


def get_html_template(
    template_file: str, replaces: Dict[str, Any]
) -> Tuple[Optional[str], Optional[str]]:

    html, plain = _get_html_template(template_file, replaces)
    header_html, header_plain = _get_html_template("email_header.html", replaces)
    footer_html, footer_plain = _get_html_template("email_footer.html", replaces)

    if (
        html is None
        or plain is None
        or header_html is None
        or header_plain is None
        or footer_html is None
        or footer_plain is None
    ):
        return None, None

    return (
        f"{header_html}{html}{footer_html}",
        f"{header_plain}{plain}{footer_plain}",
    )


def convert_html2text(html_body: str) -> str:

    h2t = html2text.HTML2Text()
    h2t.unicode_snob = False
    h2t.ignore_emphasis = True
    h2t.single_line_break = True
    h2t.ignore_images = True
    # zero for no wrap of long lines [otherwise tokens in urls will be broken]
    h2t.body_width = 0
    return h2t.handle(html_body)


def _get_html_template(
    template_file: str, replaces: Dict[str, Any]
) -> Tuple[Optional[str], Optional[str]]:
    # Custom templates from project backend/models/email/
    template_path = os.path.join(
        os.curdir, CUSTOM_PACKAGE, MODELS_DIR, "emails", template_file
    )

    if not os.path.exists(template_path):
        # Core templates from restapi/connectors/smtp/templates/
        template_path = os.path.join(
            ABS_RESTAPI_PATH,
            CONNECTORS_FOLDER,
            "smtp",
            "templates",
            template_file,
        )

    if not os.path.exists(template_path):
        log.info("Template not found: {}", template_path)
        return None, None

    try:

        templateLoader = jinja2.FileSystemLoader(
            searchpath=os.path.dirname(template_path)
        )
        templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
        template = templateEnv.get_template(template_file)

        html_body = template.render(**replaces)

        plain_body = convert_html2text(html_body)

        return html_body, plain_body
    except BaseException as e:  # pragma: no cover
        log.error("Error loading template {}: {}", template_file, e)
        return None, None


def send_notification(
    subject: str,
    template: str,
    # if None will be sent to the administrator
    to_address: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
    user: Optional[User] = None,
    send_async: bool = False,
) -> bool:

    # Always enabled during tests
    if not Connector.check_availability("smtp"):  # pragma: no cover
        return False

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

    if send_async:
        smtp_client.send_async(
            subject=subject,
            body=html_body,
            to_address=to_address,
            plain_body=plain_body,
        )
        return False

    return smtp_client.send(
        subject=subject,
        body=html_body,
        to_address=to_address,
        plain_body=plain_body,
    )


def send_registration_notification(user: User) -> None:

    # no return value since it is a send_async
    send_notification(
        subject="New user registered",
        template="new_user_registered.html",
        to_address=None,
        data=None,
        user=user,
        send_async=True,
    )


def send_activation_link(user: User, url: str) -> bool:

    return send_notification(
        subject=os.getenv("EMAIL_ACTIVATION_SUBJECT", "Account activation"),
        template="activate_account.html",
        to_address=user.email,
        data={"url": url},
        user=user,
    )


def send_password_reset_link(user: User, uri: str, reset_email: str) -> bool:

    return send_notification(
        subject="Password Reset",
        template="reset_password.html",
        to_address=reset_email,
        data={"url": uri},
        user=user,
    )


def notify_login_block(
    user: User, events: Iterator[FailedLogin], duration: int, url: str
) -> None:

    # no return value since it is a send_async
    send_notification(
        subject="Your credentials have been blocked",
        template="blocked_credentials.html",
        to_address=user.email,
        data={"events": events, "duration": seconds_to_human(duration), "url": url},
        user=user,
        send_async=True,
    )


def notify_new_credentials_to_user(user: User, unhashed_password: str) -> None:

    # no return value since it is a send_async
    send_notification(
        subject="New credentials",
        template="new_credentials.html",
        to_address=user.email,
        data={"password": unhashed_password},
        user=user,
        send_async=True,
    )


def notify_update_credentials_to_user(user: User, unhashed_password: str) -> None:

    # no return value since it is a send_async
    send_notification(
        subject="Password changed",
        template="update_credentials.html",
        to_address=user.email,
        data={"password": unhashed_password},
        user=user,
        send_async=True,
    )


def send_celery_error_notification(
    task_id: str, task_name: str, arguments: str, error_stack: Any
) -> None:

    # no return value since it is a send_async
    send_notification(
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
        send_async=True,
    )  # pragma: no cover
