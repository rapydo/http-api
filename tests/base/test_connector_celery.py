import os
import time
from datetime import timedelta

import celery
import pytest

from restapi.connectors.celery import CeleryExt, send_errors_by_email
from restapi.exceptions import ServiceUnavailable
from restapi.server import ServerModes, create_app
from restapi.services.detect import detector
from restapi.tests import BaseTests
from restapi.utilities.logs import log

CONNECTOR = "celery"


def test_celery(app, faker):

    if not detector.check_availability(CONNECTOR):
        obj = detector.get_debug_instance(CONNECTOR)
        assert obj is None
        try:
            obj = detector.get_service_instance(CONNECTOR)
            pytest("No exception raised")
        except ServiceUnavailable:
            pass

        log.warning("Skipping {} tests: service not available", CONNECTOR)
        return False

    log.info("Executing {} tests", CONNECTOR)

    # Run this before the init_services,
    # get_debug_instance is able to load what is needed
    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    detector.init_services(
        app=app,
        project_init=False,
        project_clean=False,
    )

    obj = detector.get_service_instance(CONNECTOR)
    assert obj is not None

    task_id = obj.test_task.apply_async().id

    assert task_id is not None

    if obj.variables.get("backend") == "RABBIT":
        log.warning(
            "Due to limitations on RABBIT backend task results will not be tested"
        )
    else:
        try:
            task = obj.celery_app.AsyncResult(task_id)
            assert task is not None
            r = task.get(timeout=60)
            assert r is not None
            # This is the task output, as defined in task_template.py.j2
            assert r == "Task executed!"
            assert task.status == "SUCCESS"
            assert task.result == "Task executed!"
        except celery.exceptions.TimeoutError:
            pytest.fail(f"Task timeout, result={task.result}, status={task.status}")

    if CeleryExt.CELERYBEAT_SCHEDULER is None:

        try:
            obj.get_periodic_task("does_not_exist")
            pytest.fail("get_periodic_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            obj.delete_periodic_task("does_not_exist")
            pytest.fail("delete_periodic_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            obj.create_periodic_task(
                name="task1", task="task.does.not.exists", every="60"
            )
            pytest.fail("create_periodic_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            obj.create_crontab_task(
                name="task2", task="task.does.not.exists", minute="0", hour="1"
            )
            pytest.fail("create_crontab_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except BaseException:
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
            try:
                obj.create_periodic_task(
                    name="task3",
                    task="task.does.not.exists",
                    every="60",
                    period="minutes",
                )
            except AttributeError as e:
                assert str(e) == "Unsupported period minutes for redis beat"

            obj.create_periodic_task(
                name="task3",
                task="task.does.not.exists",
                every=60,
            )
            assert obj.delete_periodic_task("task3")

            obj.create_periodic_task(
                name="task4",
                task="task.does.not.exists",
                every=timedelta(seconds=60),
            )
            assert obj.delete_periodic_task("task4")

            try:
                obj.create_periodic_task(
                    name="task5", task="task.does.not.exists", every=["60"]
                )
            except AttributeError as e:
                assert str(e) == "Invalid input parameter every = ['60'] (type list)"

        else:
            obj.create_periodic_task(
                name="task3", task="task.does.not.exists", every="60", period="minutes"
            )
            assert obj.delete_periodic_task("task3")

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    obj_id = id(obj)

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    assert id(obj) == obj_id

    time.sleep(1)

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    assert id(obj) != obj_id

    assert obj.is_connected()
    obj.disconnect()
    assert not obj.is_connected()

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with detector.get_service_instance(CONNECTOR) as obj:
        assert obj is not None

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_debug_instance("invalid")
    assert obj is None

    app = create_app(mode=ServerModes.WORKER)
    assert app is not None
    from restapi.utilities.logs import LOGS_FILE

    assert os.environ["HOSTNAME"] == "backend-server"
    assert LOGS_FILE == "backend-server"

    # this decorator is expected to be used in celery context, i.e. the self reference
    # should contains a request, injected by celery. Let's mock this by injecting an
    # artificial self
    @send_errors_by_email
    def this_function_raises_exceptions(self):
        raise AttributeError("Just an exception")

    class FakeRequest:
        def __init__(self, task_id, task, args):
            self.id = task_id
            self.task = task
            self.args = args

    class FakeSelf:
        def __init__(self, task_id, task, args):
            self.request = FakeRequest(task_id, task, args)

    task_id = faker.pystr()
    task_name = faker.pystr()
    task_args = [faker.pystr()]

    this_function_raises_exceptions(FakeSelf(task_id, task_name, task_args))

    mail = BaseTests.read_mock_email()
    assert mail.get("body") is not None

    assert f"Celery task {task_id} failed" in mail.get("body")
    assert f"Name: {task_name}" in mail.get("body")
    assert f"Arguments: {str(task_args)}" in mail.get("body")
    assert "Error: Traceback (most recent call last):" in mail.get("body")
    assert 'raise AttributeError("Just an exception")' in mail.get("body")
