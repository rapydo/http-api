import time
from datetime import timedelta

import pytest

from restapi.connectors.celery import CeleryExt
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_celery(app):

    if not detector.check_availability("celery"):
        log.warning("Skipping celery test: service not available")
        return False

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    celery = detector.get_service_instance("celery")
    assert celery is not None

    if CeleryExt.CELERYBEAT_SCHEDULER is None:

        try:
            celery.get_periodic_task("does_not_exist")
            pytest.fail("get_periodic_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            celery.delete_periodic_task("does_not_exist")
            pytest.fail("delete_periodic_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            celery.create_periodic_task(
                name="task1", task="task.does.not.exists", every="60"
            )
            pytest.fail("create_periodic_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            celery.create_crontab_task(
                name="task2", task="task.does.not.exists", minute="0", hour="1"
            )
            pytest.fail("create_crontab_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"
        except BaseException:
            pytest.fail("Unexpected exception raised")

    else:
        assert celery.get_periodic_task("does_not_exist") is None
        assert not celery.delete_periodic_task("does_not_exist")

        celery.create_periodic_task(
            name="task1", task="task.does.not.exists", every="60"
        )

        assert celery.delete_periodic_task("task1")
        assert not celery.delete_periodic_task("task1")

        celery.create_periodic_task(
            name="task1_bis",
            task="task.does.not.exists",
            every="60",
            period="seconds",
            args=["a", "b", "c"],
            kwargs={"a": 1, "b": 2, "c": 3},
        )

        assert celery.delete_periodic_task("task1_bis")
        assert not celery.delete_periodic_task("task1_bis")

        # cron at 01:00
        celery.create_crontab_task(
            name="task2", task="task.does.not.exists", minute="0", hour="1"
        )

        assert celery.delete_periodic_task("task2")
        assert not celery.delete_periodic_task("task2")

        celery.create_crontab_task(
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

        assert celery.delete_periodic_task("task2_bis")
        assert not celery.delete_periodic_task("task2_bis")

        if CeleryExt.CELERYBEAT_SCHEDULER == "REDIS":
            try:
                celery.create_periodic_task(
                    name="task3",
                    task="task.does.not.exists",
                    every="60",
                    period="minutes",
                )
            except AttributeError as e:
                assert str(e) == "Unsupported period minutes for redis beat"

            celery.create_periodic_task(
                name="task3", task="task.does.not.exists", every=60,
            )
            assert celery.delete_periodic_task("task3")

            celery.create_periodic_task(
                name="task4", task="task.does.not.exists", every=timedelta(seconds=60),
            )
            assert celery.delete_periodic_task("task4")

            try:
                celery.create_periodic_task(
                    name="task5", task="task.does.not.exists", every=["60"]
                )
            except AttributeError as e:
                assert str(e) == "Invalid input parameter every = ['60'] (type list)"

        else:
            celery.create_periodic_task(
                name="task3", task="task.does.not.exists", every="60", period="minutes"
            )
            assert celery.delete_periodic_task("task3")

    celery = detector.get_service_instance("celery", cache_expiration=1)
    obj_id = id(celery)

    celery = detector.get_service_instance("celery", cache_expiration=1)
    assert id(celery) == obj_id

    time.sleep(1)

    celery = detector.get_service_instance("celery", cache_expiration=1)
    assert id(celery) != obj_id

    # Close connection...
    celery.disconnect()

    # Test connection... should fail!
    # ??

    # ... close connection again ... nothing should happens
    celery.disconnect()

    with detector.get_service_instance("celery") as obj:
        assert obj is not None
