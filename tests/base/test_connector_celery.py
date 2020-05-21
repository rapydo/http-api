# -*- coding: utf-8 -*-
import pytest
from datetime import timedelta
from restapi.connectors.celery import CeleryExt
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_celery():

    if not detector.check_availability('celery'):
        log.warning("Skipping celery test: service not available")
        return False

    detector.get_service_instance("celery")

    if CeleryExt.CELERYBEAT_SCHEDULER is None:

        try:
            CeleryExt.get_periodic_task('does_not_exist')
            pytest.fail("get_periodic_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"

        try:
            CeleryExt.delete_periodic_task('does_not_exist')
            pytest.fail("delete_periodic_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"

        try:
            CeleryExt.create_periodic_task(
                name='task1',
                task='task.does.not.exists',
                every='60'
            )
            pytest.fail("create_periodic_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"

        try:
            CeleryExt.create_crontab_task(
                name='task2',
                task='task.does.not.exists',
                minute='0',
                hour='1'
            )
            pytest.fail("create_crontab_task with unknown CELERYBEAT_SCHEDULER")
        except AttributeError as e:
            assert str(e) == "Unsupported celery-beat scheduler: None"

    else:
        assert CeleryExt.get_periodic_task('does_not_exist') is None
        assert not CeleryExt.delete_periodic_task('does_not_exist')

        CeleryExt.create_periodic_task(
            name='task1',
            task='task.does.not.exists',
            every='60'
        )

        assert CeleryExt.delete_periodic_task('task1')
        assert not CeleryExt.delete_periodic_task('task1')

        CeleryExt.create_periodic_task(
            name='task1_bis',
            task='task.does.not.exists',
            every='60',
            period='seconds',
            args=['a', 'b', 'c'],
            kwargs={'a': 1, 'b': 2, 'c': 3}
        )

        assert CeleryExt.delete_periodic_task('task1_bis')
        assert not CeleryExt.delete_periodic_task('task1_bis')

        # cron at 01:00
        CeleryExt.create_crontab_task(
            name='task2',
            task='task.does.not.exists',
            minute='0',
            hour='1'
        )

        assert CeleryExt.delete_periodic_task('task2')
        assert not CeleryExt.delete_periodic_task('task2')

        CeleryExt.create_crontab_task(
            name='task2_bis',
            task='task.does.not.exists',
            minute='0',
            hour='1',
            day_of_week="*",
            day_of_month="*",
            month_of_year="*",
            args=['a', 'b', 'c'],
            kwargs={'a': 1, 'b': 2, 'c': 3}
        )

        assert CeleryExt.delete_periodic_task('task2_bis')
        assert not CeleryExt.delete_periodic_task('task2_bis')

        if CeleryExt.CELERYBEAT_SCHEDULER == 'REDIS':
            try:
                CeleryExt.create_periodic_task(
                    name='task3',
                    task='task.does.not.exists',
                    every='60',
                    period='minutes'
                )
            except AttributeError as e:
                assert str(e) == 'Unsupported period minutes for redis beat'

            CeleryExt.create_periodic_task(
                name='task3',
                task='task.does.not.exists',
                every=60,
            )
            assert CeleryExt.delete_periodic_task('task3')

            CeleryExt.create_periodic_task(
                name='task4',
                task='task.does.not.exists',
                every=timedelta(seconds=60),
            )
            assert CeleryExt.delete_periodic_task('task4')

            try:
                CeleryExt.create_periodic_task(
                    name='task5',
                    task='task.does.not.exists',
                    every=['60']
                )
            except AttributeError as e:
                assert str(e) == "Invalid input parameter every = ['60'] (type list)"

        else:
            CeleryExt.create_periodic_task(
                name='task3',
                task='task.does.not.exists',
                every='60',
                period='minutes'
            )
            assert CeleryExt.delete_periodic_task('task3')
