# -*- coding: utf-8 -*-

from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_celery():

    if not detector.check_availability('celery'):
        log.warning("Skipping celery test: service not available")
        return False

    celery = detector.connectors_instances.get('celery').get_instance()

    if celery.CELERYBEAT_SCHEDULER is None:
        log.warning("Skipping celery beat tests: service not available")
    else:
        assert celery.get_periodic_task('does_not_exist') is None
