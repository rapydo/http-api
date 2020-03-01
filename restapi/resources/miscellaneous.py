# -*- coding: utf-8 -*-

from flask import jsonify

from restapi.protocols.bearer import authentication
from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector
from restapi.exceptions import RestApiException
from restapi import decorators as decorate

from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.globals import mem
from restapi.utilities.logs import log

"""
class Status
    GET: return a standard message if API are reachable

class Verify
    GET: verify connection to a single service

class SwaggerSpecifications
    GET: return swagger specs

class Queue
    GET: get list of celery tasks
    PUT: revoke a (not running) task
    DELETE: terminate (if running) and revoke a task

"""


class Status(EndpointResource):
    """ API online client testing """

    labels = ['helpers']

    GET = {
        "/status": {
            "summary": "Check if the API server is currently reachable",
            "description": "You may use this URI to monitor network or server problems.",
            "responses": {"200": {"description": "Server is alive!"}},
        }
    }

    @decorate.catch_error()
    def get(self, service=None):

        return self.force_response('Server is alive!')


class Verify(EndpointResource):
    """ Service connection testing """

    labels = ["helpers"]
    GET = {
        "/status/<service>": {
            "summary": "Check if the API server is able to reach the given service",
            "description": "You may use this URI to monitor the network link between API server and a given service",
            "responses": {
                "200": {"description": "Server is able to reach the service!"}
            },
        }
    }

    @decorate.catch_error()
    @authentication.required(roles=['admin_root'])
    def get(self, service):

        log.critical(detector.available_services)
        if not detector.check_availability(service):
            raise RestApiException(
                "Unknown service: {}".format(service),
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED,
            )

        service_instance = self.get_service_instance(service, global_instance=False)
        log.critical(service_instance)
        return self.force_response("Service is reachable: {}".format(service))


class SwaggerSpecifications(EndpointResource):
    """
    Specifications output throught Swagger (open API) standards
    """

    labels = ["specifications"]

    GET = {
        "/specs": {
            "summary": "Specifications output throught Swagger (open API) standards",
            "responses": {
                "200": {
                    "description": "a JSON with all endpoint defined with Swagger standards"
                }
            },
        }
    }

    def get(self):

        # NOTE: swagger dictionary is read only once, at server init time
        swagjson = mem.customizer._definitions

        # NOTE: changing dinamically options, based on where the client lies
        from restapi.confs import PRODUCTION
        from restapi.confs import get_api_url
        from flask import request

        api_url = get_api_url(request, PRODUCTION)
        scheme, host = api_url.rstrip('/').split('://')
        swagjson['host'] = host
        swagjson['schemes'] = [scheme]

        # Jsonify, so we skip custom response building
        return jsonify(swagjson)


###########################
# In case you have celery queue,
# you get a queue endpoint for free
if detector.check_availability('celery'):

    class Queue(EndpointResource):

        depends_on = ["CELERY_ENABLE"]
        labels = ["tasks"]
        GET = {
            "/queue": {
                "summary": "List tasks in the queue",
                "description": "Base implementation of a CELERY queue.",
                "responses": {"200": {"description": "A list of tasks"}},
            },
            "/queue/<task_id>": {
                "summary": "Information about a single task",
                "responses": {"200": {"description": "task information"}},
            },
        }
        PUT = {
            "/queue/<task_id>": {
                "summary": "Revoke a task from its id",
                "responses": {"204": {"description": "The task was revoked"}},
            }
        }
        DELETE = {
            "/queue/<task_id>": {
                "summary": "Delete a task",
                "responses": {
                    "204": {
                        "description": "The task with specified id was succesfully deleted"
                    }
                },
            }
        }

        # task_id = uuid referring to the task you are selecting
        @authentication.required(
            roles=['admin_root', 'staff_user'], required_roles='any'
        )
        def get(self, task_id=None):

            data = []
            # Inspect all worker nodes
            celery = self.get_service_instance('celery')

            if task_id is not None:
                task_result = celery.AsyncResult(task_id)
                res = task_result.result
                if not isinstance(res, dict):
                    res = str(res)
                return self.force_response({
                    'status': task_result.status,
                    # 'info': task_result.info,
                    'output': res,
                })

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
                log.debug('checked worker: {}', worker)
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
                    if task_id is not None and task["request"]["id"] != task_id:
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
                    if task_id is not None and task["id"] != task_id:
                        continue

                    data.append(
                        {
                            'status': 'SCHEDULED',
                            'worker': worker,
                            'ETA': task['time_start'],
                            'task_id': task["id"],
                            'priority': task['delivery_info']["priority"],
                            'task': task["name"],
                            'args': task["args"],
                        }
                    )

            # from celery.task.control import inspect
            # tasks = inspect()
            log.verbose('listing completed')

            return self.force_response(data)

        # task_id = uuid referring to the task you are selecting
        @authentication.required(roles=['admin_root'])
        def put(self, task_id):
            celery = self.get_service_instance('celery')
            celery.control.revoke(task_id)
            return self.empty_response()

        # task_id = uuid referring to the task you are selecting
        @authentication.required(roles=['admin_root'])
        def delete(self, task_id):
            celery = self.get_service_instance('celery')
            celery.control.revoke(task_id, terminate=True)
            return self.empty_response()
