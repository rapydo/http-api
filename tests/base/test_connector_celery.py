import os
import time
from datetime import timedelta

import celery
import pytest
from faker import Faker
from flask import Flask

from restapi.config import get_project_configuration
from restapi.connectors import Connector
from restapi.connectors import celery as connector
from restapi.connectors.celery import CeleryExt, Ignore
from restapi.exceptions import BadRequest, ServiceUnavailable
from restapi.server import ServerModes, create_app
from restapi.tests import BaseTests
from restapi.utilities.logs import log

CONNECTOR = "celery"


def test_celery(app: Flask, faker: Faker) -> None:

    if not Connector.check_availability(CONNECTOR):

        try:
            obj = connector.get_instance()
            pytest.fail("No exception raised")  # pragma: no cover
        except ServiceUnavailable:
            pass

        log.warning("Skipping {} tests: service not available", CONNECTOR)
        return None

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
    task_output = BaseTests.send_task(app, "test_task", "wrong")

    assert task_output is None

    mail = BaseTests.read_mock_email()
    project_tile = get_project_configuration("project.title", default="YourProject")

    body = mail.get("body")
    headers = mail.get("headers")
    assert body is not None
    assert headers is not None
    assert f"Subject: {project_tile}: Task test_task failed" in headers
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
    try:
        BaseTests.send_task(app, "test_task", "ignore")
        pytest.fail("No expcetion raised")  # pragma: no cover
    # the errors decorator re-raise the Ignore exception, without any further action
    except Ignore:
        mail = BaseTests.read_mock_email()
        # No email is raised with Ignore exceptions
        assert mail is None

    try:
        BaseTests.send_task(app, "does-not-exist")
        pytest.fail("No exception raised")  # pragma: no cover
    except AttributeError as e:
        assert str(e) == "Task not found"

    if obj.variables.get("backend") == "RABBIT":
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

    if CeleryExt.CELERYBEAT_SCHEDULER is None:

        try:
            obj.get_periodic_task("does_not_exist")
            pytest.fail(
                "get_periodic_task with unknown CELERYBEAT_SCHEDULER"
            )  # pragma: no cover
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except Exception:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            obj.delete_periodic_task("does_not_exist")
            pytest.fail(
                "delete_periodic_task with unknown CELERYBEAT_SCHEDULER"
            )  # pragma: no cover
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except Exception:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            obj.create_periodic_task(
                name="task1", task="task.does.not.exists", every="60"
            )
            pytest.fail(
                "create_periodic_task with unknown CELERYBEAT_SCHEDULER"
            )  # pragma: no cover
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except Exception:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            obj.create_crontab_task(
                name="task2", task="task.does.not.exists", minute="0", hour="1"
            )
            pytest.fail(
                "create_crontab_task with unknown CELERYBEAT_SCHEDULER"
            )  # pragma: no cover
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except Exception:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

    else:
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

            try:
                obj.create_periodic_task(
                    name="task8",
                    task="task.does.not.exists",
                    every="60",
                    period="years",  # type: ignore
                )
            except BadRequest as e:
                assert str(e) == "Invalid timedelta period: years"

            obj.create_periodic_task(
                name="task9",
                task="task.does.not.exists",
                every=timedelta(seconds=60),
            )
            assert obj.delete_periodic_task("task9")

            try:
                obj.create_periodic_task(
                    name="task10",
                    task="task.does.not.exists",
                    every=["60"],  # type: ignore
                )
            except AttributeError as e:
                assert str(e) == "Invalid input parameter every = ['60'] (type list)"

            try:
                obj.create_periodic_task(
                    name="task11",
                    task="task.does.not.exists",
                    every="invalid",
                )
            except AttributeError as e:
                assert str(e) == "Invalid input parameter every = invalid (type str)"

        else:
            obj.create_periodic_task(
                name="task3", task="task.does.not.exists", every="60", period="minutes"
            )
            assert obj.delete_periodic_task("task3")

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

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with connector.get_instance() as obj:
        assert obj is not None

    app = create_app(mode=ServerModes.WORKER)
    assert app is not None
