import os
import time
from datetime import timedelta

import pytest

from restapi.connectors.celery import CeleryExt
from restapi.server import create_app
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "celery"


def test_celery(app):

    if not detector.check_availability(CONNECTOR):
        obj = detector.get_debug_instance(CONNECTOR)
        assert obj is None

        log.warning("Skipping celery test: service not available")
        return False

    # Run this before the init_services,
    # get_debug_instance is able to load what is needed
    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    obj = detector.get_service_instance(CONNECTOR)
    assert obj is not None

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
                name="task3", task="task.does.not.exists", every=60,
            )
            assert obj.delete_periodic_task("task3")

            obj.create_periodic_task(
                name="task4", task="task.does.not.exists", every=timedelta(seconds=60),
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

    # Close connection...
    obj.disconnect()

    # Test connection... should fail!
    # ??

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with detector.get_service_instance(CONNECTOR) as obj:
        assert obj is not None

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_debug_instance("invalid")
    assert obj is None

    app = create_app(worker_mode=True)
    assert app is not None
    from restapi.utilities.logs import LOGS_FILE

    assert os.environ["HOSTNAME"] == "backend-server"
    assert LOGS_FILE == "backend-server"
