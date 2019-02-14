# -*- coding: utf-8 -*-

from flask import jsonify

from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector
from restapi.exceptions import RestApiException
from restapi import decorators as decorate

from utilities import htmlcodes as hcodes
from utilities.globals import mem
from utilities.logs import get_logger

log = get_logger(__name__)

"""
class Status
    GET: return a standard message if API are reachable

class Verify
    GET: verify connection to a single service

class SwaggerSpecifications
    GET: return swagger specs

class Internal
    GET: return a standard message if user has role Internal

class Admin
    GET: return a standard message if user has role Admin

class Queue
    GET: get list of celery tasks
    PUT: revoke a (not running) task
    DELETE: terminate (if running) and revoke a task

"""


class Status(EndpointResource):
    """ API online client testing """

    @decorate.catch_error()
    def get(self, service=None):

        return 'Server is alive!'


class Verify(EndpointResource):
    """ Service connection testing """

    @decorate.catch_error()
    def get(self, service):

        log.critical(detector.available_services)
        if not detector.check_availability(service):
            raise RestApiException(
                "Unknown service: %s" % service,
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED
            )

        service_instance = self.get_service_instance(
            service, global_instance=False)
        log.critical(service_instance)
        return "Service is reachable: %s" % service


class SwaggerSpecifications(EndpointResource):
    """
    Specifications output throught Swagger (open API) standards
    """

    def get(self):

        # NOTE: swagger dictionary is read only once, at server init time
        swagjson = mem.customizer._definitions

        # NOTE: changing dinamically options, based on where the client lies
        from restapi.confs import PRODUCTION
        from flask import request
        from utilities.helpers import get_api_url
        api_url = get_api_url(request, PRODUCTION)
        scheme, host = api_url.rstrip('/').split('://')
        swagjson['host'] = host
        swagjson['schemes'] = [scheme]

        # Jsonify, so we skip custom response building
        return jsonify(swagjson)


class Internal(EndpointResource):
    """ Token and Role authentication test """

    def get(self):
        return "I am internal"


class Admin(EndpointResource):
    """ Token and Role authentication test """

    def get(self):
        return "I am admin!"


###########################
# In case you have celery queue,
# you get a queue endpoint for free
if detector.check_availability('celery'):

    class Queue(EndpointResource):

        def get(self, task_id=None):

            data = []
            # Inspect all worker nodes
            celery = self.get_service_instance('celery')

            if task_id is not None:
                task_result = celery.AsyncResult(task_id)
                res = task_result.result
                if not isinstance(res, dict):
                    res = str(res)
                return {
                    'status': task_result.status,
                    # 'info': task_result.info,
                    'output': res,
                }

            #############################
            # FAST WAY
            stats = celery.control.inspect().stats()
            workers = list(stats.keys())

            active_tasks = {}
            revoked_tasks = {}
            scheduled_tasks = {}
            reserved_tasks = {}

            for worker in workers:
                i = celery.control.inspect([worker])
                log.debug('checked worker: %s', worker)
                for key, value in i.active().items():
                    active_tasks[key] = value
                for key, value in i.revoked().items():
                    revoked_tasks[key] = value
                for key, value in i.reserved().items():
                    reserved_tasks[key] = value
                for key, value in i.scheduled().items():
                    scheduled_tasks[key] = value

            #############################
            # workers = celery.control.inspect()
            # SLOW WAY
            # active_tasks = workers.active()
            # revoked_tasks = workers.revoked()
            # reserved_tasks = workers.reserved()
            # scheduled_tasks = workers.scheduled()
            # SLOW WAY
            # if active_tasks is None:
            #     active_tasks = []
            # if revoked_tasks is None:
            #     revoked_tasks = []
            # if scheduled_tasks is None:
            #     scheduled_tasks = []
            # if reserved_tasks is None:
            #     reserved_tasks = []

            log.verbose('listing items')
            for worker, tasks in active_tasks.items():
                for task in tasks:
                    if task_id is not None and task["id"] != task_id:
                        continue

                    row = {}
                    row['status'] = 'ACTIVE'
                    row['worker'] = worker
                    row['ETA'] = task["time_start"]
                    row['task_id'] = task["id"]
                    row['task'] = task["name"]
                    row['args'] = task["args"]

                    if task_id is not None:
                        task_result = celery.AsyncResult(task_id)
                        row['task_status'] = task_result.status
                        row['info'] = task_result.info
                    data.append(row)

            for worker, tasks in revoked_tasks.items():
                for task in tasks:
                    if task_id is not None and task != task_id:
                        continue
                    row = {}
                    row['status'] = 'REVOKED'
                    row['task_id'] = task
                    data.append(row)

            for worker, tasks in scheduled_tasks.items():
                for task in tasks:
                    if task_id is not None and \
                       task["request"]["id"] != task_id:
                        continue

                    row = {}
                    row['status'] = 'SCHEDULED'
                    row['worker'] = worker
                    row['ETA'] = task["eta"]
                    row['task_id'] = task["request"]["id"]
                    row['priority'] = task["priority"]
                    row['task'] = task["request"]["name"]
                    row['args'] = task["request"]["args"]
                    data.append(row)

            for worker, tasks in reserved_tasks.items():
                for task in tasks:
                    if task_id is not None and \
                       task["id"] != task_id:
                        continue

                    data.append({
                        'status': 'SCHEDULED',
                        'worker': worker,
                        'ETA': task['time_start'],
                        'task_id': task["id"],
                        'priority': task['delivery_info']["priority"],
                        'task': task["name"],
                        'args': task["args"],
                    })

            # from celery.task.control import inspect
            # tasks = inspect()
            log.verbose('listing completed')

            return self.force_response(data)

        def put(self, task_id):
            celery = self.get_service_instance('celery')
            celery.control.revoke(task_id)
            return self.empty_response()

        def delete(self, task_id):
            celery = self.get_service_instance('celery')
            celery.control.revoke(task_id, terminate=True)
            return self.empty_response()
