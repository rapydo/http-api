# -*- coding: utf-8 -*-

from restapi.connectors.celery import CeleryExt
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_celery():

    if not detector.check_availability('celery'):
        log.warning("Skipping celery test: service not available")
        return False

    detector.connectors_instances.get('celery').get_instance()

    if CeleryExt.CELERYBEAT_SCHEDULER is None:
        log.warning("Skipping celery beat tests: service not available")
    else:
        assert CeleryExt.get_periodic_task('does_not_exist') is None
        assert not CeleryExt.delete_periodic_task('does_not_exist')

        CeleryExt.create_periodic_task(
            name='task1',
            task='task.does.not.exists',
            every='60'
        )

        assert CeleryExt.delete_periodic_task('task1')

        # cron at 01:00
        CeleryExt.create_crontab_task(
            name='task2',
            task='task.does.not.exists',
            minute='0',
            hour='1'
        )

        assert CeleryExt.delete_periodic_task('task2')
