import time
from datetime import timedelta
from unittest.mock import patch

import celery
import pytest
from faker import Faker
from flask import Flask

from restapi.config import get_project_configuration
from restapi.connectors import Connector
from restapi.connectors import celery as connector
from restapi.connectors.celery import CeleryExt, CeleryRetryTask, Ignore
from restapi.env import Env
from restapi.exceptions import BadRequest, ServiceUnavailable
from restapi.server import ServerModes, create_app
from restapi.tests import BaseTests
from restapi.utilities.logs import log

CONNECTOR = "celery"
CONNECTOR_AVAILABLE = Connector.check_availability(CONNECTOR)


@pytest.mark.skipif(
    CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be not available"
)
def test_no_celery() -> None:
    with pytest.raises(ServiceUnavailable):
        connector.get_instance()

    log.warning("Skipping {} tests: service not available", CONNECTOR)
    return None


@pytest.mark.skipif(
    not CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be available"
)
def test_celery(app: Flask, faker: Faker) -> None:
    log.info("Executing {} tests", CONNECTOR)

    obj = connector.get_instance()
    assert obj is not None

    task = obj.celery_app.send_task("test_task", args=("myinput",))

    assert task is not None
    assert task.id is not None

    # Mocked task
    task_output = BaseTests.send_task(app, "test_task", "myinput")

    # As defined in task template
    assert task_output == "Task executed!"

    # wrong is a special value included in tasks template
    with pytest.raises(Ignore):
        BaseTests.send_task(app, "test_task", "wrong")

    project_title = get_project_configuration("project.title", default="YourProject")

    mail = BaseTests.read_mock_email()

    body = mail.get("body")
    headers = mail.get("headers")
    assert body is not None
    assert headers is not None
    assert f"Subject: {project_title}: Task test_task failed" in headers
    assert "this email is to notify you that a Celery task failed!" in body
    # fixed-id is a mocked value set in TESTING mode by @task in Celery connector
    assert "Task ID: fixed-id" in body
    assert "Task name: test_task" in body
    assert "Arguments: ('wrong',)" in body
    assert "Error Stack" in body
    assert "Traceback (most recent call last):" in body

    exc = (
        "AttributeError: "
        "You can raise exceptions to stop the task execution in case of errors"
    )
    assert exc in body

    # celery.exceptions.Ignore exceptions are ignored

    BaseTests.delete_mock_email()
    # ignore is a special value included in tasks template
    with pytest.raises(Ignore):
        BaseTests.send_task(app, "test_task", "ignore")
    # the errors decorator re-raise the Ignore exception, without any further action
    # No email is sent in case of Ignore exceptions
    with pytest.raises(FileNotFoundError):
        mail = BaseTests.read_mock_email()

    # retry is a special value included in tasks template
    with pytest.raises(CeleryRetryTask):
        BaseTests.send_task(app, "test_task", "retry")

    mail = BaseTests.read_mock_email()

    body = mail.get("body")
    headers = mail.get("headers")
    assert body is not None
    assert headers is not None
    assert f"Subject: {project_title}: Task test_task failed (failure #1)" in headers
    assert "this email is to notify you that a Celery task failed!" in body
    # fixed-id is a mocked value set in TESTING mode by @task in Celery connector
    assert "Task ID: fixed-id" in body
    assert "Task name: test_task" in body
    assert "Arguments: ('retry',)" in body
    assert "Error Stack" in body
    assert "Traceback (most recent call last):" in body

    exc = "CeleryRetryTask: Force the retry of this task"
    assert exc in body

    # retry2 is a special value included in tasks template
    # Can't easily import the custom exception defined in the task...
    # a generic exception is enough here
    with pytest.raises(Exception):
        BaseTests.send_task(app, "test_task", "retry2")

    mail = BaseTests.read_mock_email()

    body = mail.get("body")
    headers = mail.get("headers")
    assert body is not None
    assert headers is not None
    assert f"Subject: {project_title}: Task test_task failed (failure #1)" in headers
    assert "this email is to notify you that a Celery task failed!" in body
    # fixed-id is a mocked value set in TESTING mode by @task in Celery connector
    assert "Task ID: fixed-id" in body
    assert "Task name: test_task" in body
    assert "Arguments: ('retry2',)" in body
    assert "Error Stack" in body
    assert "Traceback (most recent call last):" in body

    exc = "MyException: Force the retry of this task by using a custom exception"
    assert exc in body

    with pytest.raises(AttributeError, match=r"Task not found"):
        BaseTests.send_task(app, "does-not-exist")

    if obj.variables.get("backend_service") == "RABBIT":
        log.warning(
            "Due to limitations on RABBIT backend task results will not be tested"
        )
    else:
        try:
            r = task.get(timeout=10)
            assert r is not None
            # This is the task output, as defined in task_template.py.j2
            assert r == "Task executed!"
            assert task.status == "SUCCESS"
            assert task.result == "Task executed!"
        except celery.exceptions.TimeoutError:  # pragma: no cover
            pytest.fail(f"Task timeout, result={task.result}, status={task.status}")

    obj.disconnect()

    # a second disconnect should not raise any error
    obj.disconnect()

    # Create new connector with short expiration time
    obj = connector.get_instance(expiration=2, verification=1)
    obj_id = id(obj)

    # Connector is expected to be still valid
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) == obj_id

    time.sleep(1)

    # The connection should have been checked and should be still valid
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) == obj_id

    time.sleep(1)

    # Connection should have been expired and a new connector been created
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) != obj_id

    assert obj.is_connected()
    obj.disconnect()
    assert not obj.is_connected()

    # ... close connection again ... nothing should happen
    obj.disconnect()

    with connector.get_instance() as obj:
        assert obj is not None

    app = create_app(name="Flask Tests", mode=ServerModes.WORKER, options={})
    assert app is not None


@pytest.mark.skipif(
    not CONNECTOR_AVAILABLE or Env.get_bool("CELERYBEAT_ENABLED"),
    reason="This test needs celery-beat to be NOT available",
)
def test_no_celerybeat() -> None:
    obj = connector.get_instance()
    assert obj is not None

    with pytest.raises(
        AttributeError, match=r"Unsupported celery-beat scheduler: None"
    ):
        # get_periodic_task with unknown CELERYBEAT_SCHEDULER
        obj.get_periodic_task("does_not_exist")

    with pytest.raises(
        AttributeError, match=r"Unsupported celery-beat scheduler: None"
    ):
        # delete_periodic_task with unknown CELERYBEAT_SCHEDULER
        obj.delete_periodic_task("does_not_exist")

    with pytest.raises(
        AttributeError, match=r"Unsupported celery-beat scheduler: None"
    ):
        # create_periodic_task with unknown CELERYBEAT_SCHEDULER
        obj.create_periodic_task(name="task1", task="task.does.not.exists", every="60")

    with pytest.raises(
        AttributeError, match=r"Unsupported celery-beat scheduler: None"
    ):
        # create_crontab_task with unknown CELERYBEAT_SCHEDULER
        obj.create_crontab_task(
            name="task2", task="task.does.not.exists", minute="0", hour="1"
        )


@pytest.mark.skipif(
    not CONNECTOR_AVAILABLE or not Env.get_bool("CELERYBEAT_ENABLED"),
    reason="This test needs celery-beat to be available",
)
def test_celerybeat() -> None:
    obj = connector.get_instance()
    assert obj is not None

    assert obj.get_periodic_task("does_not_exist") is None
    assert not obj.delete_periodic_task("does_not_exist")

    obj.create_periodic_task(name="task1", task="task.does.not.exists", every="60")

    assert obj.delete_periodic_task("task1")
    assert not obj.delete_periodic_task("task1")

    obj.create_periodic_task(
        name="task1_bis",
        task="task.does.not.exists",
        every="60",
        period="seconds",
        args=["a", "b", "c"],
        kwargs={"a": 1, "b": 2, "c": 3},
    )

    assert obj.delete_periodic_task("task1_bis")
    assert not obj.delete_periodic_task("task1_bis")

    # cron at 01:00
    obj.create_crontab_task(
        name="task2", task="task.does.not.exists", minute="0", hour="1"
    )

    assert obj.delete_periodic_task("task2")
    assert not obj.delete_periodic_task("task2")

    obj.create_crontab_task(
        name="task2_bis",
        task="task.does.not.exists",
        minute="0",
        hour="1",
        day_of_week="*",
        day_of_month="*",
        month_of_year="*",
        args=["a", "b", "c"],
        kwargs={"a": 1, "b": 2, "c": 3},
    )

    assert obj.delete_periodic_task("task2_bis")
    assert not obj.delete_periodic_task("task2_bis")

    if CeleryExt.CELERYBEAT_SCHEDULER == "REDIS":
        obj.create_periodic_task(
            name="task3",
            task="task.does.not.exists",
            every=60,
        )
        assert obj.delete_periodic_task("task3")

        obj.create_periodic_task(
            name="task4", task="task.does.not.exists", every=60, period="seconds"
        )
        assert obj.delete_periodic_task("task4")

        obj.create_periodic_task(
            name="task5", task="task.does.not.exists", every=60, period="minutes"
        )
        assert obj.delete_periodic_task("task5")

        obj.create_periodic_task(
            name="task6", task="task.does.not.exists", every=60, period="hours"
        )
        assert obj.delete_periodic_task("task6")

        obj.create_periodic_task(
            name="task7", task="task.does.not.exists", every=60, period="days"
        )
        assert obj.delete_periodic_task("task7")

        with pytest.raises(BadRequest, match=r"Invalid timedelta period: years"):
            obj.create_periodic_task(
                name="task8",
                task="task.does.not.exists",
                every="60",
                period="years",  # type: ignore
            )

        obj.create_periodic_task(
            name="task9",
            task="task.does.not.exists",
            every=timedelta(seconds=60),
        )
        assert obj.delete_periodic_task("task9")

        with pytest.raises(
            AttributeError,
            match=r"Invalid input parameter every = \['60'\] \(type list\)",
        ):
            obj.create_periodic_task(
                name="task10",
                task="task.does.not.exists",
                every=["60"],  # type: ignore
            )

        with pytest.raises(
            AttributeError,
            match=r"Invalid input parameter every = invalid \(type str\)",
        ):
            obj.create_periodic_task(
                name="task11",
                task="task.does.not.exists",
                every="invalid",
            )
