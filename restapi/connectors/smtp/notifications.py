from typing import Any, Dict, Iterator, Optional, Tuple

import html2text
import jinja2

from restapi.config import (
    ABS_RESTAPI_PATH,
    CODE_DIR,
    CUSTOM_PACKAGE,
    MODELS_DIR,
    get_frontend_url,
    get_project_configuration,
)
from restapi.connectors import CONNECTORS_FOLDER, Connector, smtp
from restapi.connectors.smtp import Mail
from restapi.env import Env
from restapi.services.authentication import Login, User
from restapi.utilities.logs import log
from restapi.utilities.time import seconds_to_human


def get_html_template(
    template_file: str, replaces: Dict[str, Any]
) -> Tuple[Optional[str], Optional[str]]:

    html = _get_html_template(template_file, replaces)
    header_html = _get_html_template("email_header.html", replaces)
    footer_html = _get_html_template("email_footer.html", replaces)

    if html is None or header_html is None or footer_html is None:
        return None, None

    html_body = f"{header_html}{html}{footer_html}"
    plain_body = convert_html2text(html_body)
    return html_body, plain_body


def convert_html2text(html_body: str) -> str:

    h2t = html2text.HTML2Text()
    h2t.unicode_snob = False
    h2t.ignore_emphasis = True
    h2t.single_line_break = True
    h2t.ignore_images = True
    # zero for no wrap of long lines [otherwise tokens in urls will be broken]
    # but since the maximum allowed line length on email is 998 octets
    # I set a very long wrap, that should not break any tokens
    h2t.body_width = 512
    return h2t.handle(html_body)


def _get_html_template(template_file: str, replaces: Dict[str, Any]) -> Optional[str]:
    # Custom templates from project backend/models/email/
    template_path = CODE_DIR.joinpath(
        CUSTOM_PACKAGE, MODELS_DIR, "emails", template_file
    )

    if not template_path.exists():
        # Core templates from restapi/connectors/smtp/templates/
        template_path = ABS_RESTAPI_PATH.joinpath(
            CONNECTORS_FOLDER,
            "smtp",
            "templates",
            template_file,
        )

    if not template_path.exists():
        log.info("Template not found: {}", template_path)
        return None

    try:

        templateLoader = jinja2.FileSystemLoader(searchpath=template_path.parent)
        templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
        template = templateEnv.get_template(template_file)

        replaces.setdefault("host", get_frontend_url())

        return template.render(**replaces)
    except Exception as e:  # pragma: no cover
        log.error("Error loading template {}: {}", template_file, e)
        return None


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
    reply_to = Env.get("SMTP_NOREPLY", Env.get("SMTP_ADMIN", ""))

    if data is None:
        data = {}

    data.setdefault("project", title)
    data.setdefault("reply_to", reply_to)

    if user:
        data.setdefault("username", user.email)
        data.setdefault("name", user.name)
        data.setdefault("surname", user.surname)

    html_body, plain_body = get_html_template(template, data)

    if not html_body:  # pragma: no cover
        log.error("Can't load {}", template)
        return False

    subject = f"{title}: {subject}"

    if send_async:
        Mail.send_async(
            subject=subject,
            body=html_body,
            to_address=to_address,
            plain_body=plain_body,
        )
        return False

    smtp_client = smtp.get_instance()
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
        subject=Env.get("EMAIL_ACTIVATION_SUBJECT", "Account activation"),
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
    user: User, events: Iterator[Login], duration: int, url: str
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
    )
