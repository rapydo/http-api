# -*- coding: utf-8 -*-

# TOFIX: import logger?


class InvalidArgument(BaseException):
    pass


class NotImplementedAction(BaseException):
    pass


class ImplementedActions(object):

    def __init__(self, compose, vanilla_services):
        self._compose_project = compose
        self._vanilla_services = vanilla_services

    def _exec(self, command):
        print ("\nCommand to be executed:\n\tdocker-compose %s\n\n" % command)

    def service_mandatory(self, service):
        if service is None:
            raise InvalidArgument(
                'Service parameter is mandatory for this action'
            )

    def service_incompatible(self, service):
        if service is not None:
            raise InvalidArgument(
                'Service parameter is incompatible with this action'
            )

    def do_check(self, project, action, service, **kwargs):
        self.service_incompatible(service)
        raise NotImplementedAction(
            'verify if the %s blueprint is well-configured ' +
            '[verify all blueprint-specific dir and configuration files]'
            % project
        )

    def do_init(self, command, project, action, service, **kwargs):
        self.service_incompatible(service)
        raise NotImplementedAction(
            'init the %s blueprint (in old do command) ' +
            '[clone backend and frontend, pull docker images, pull bower libs'
            % project
        )

    def do_update(self, command, project, action, **kwargs):
        print("TEST", self._compose_project)

        # TODO: git pull
        # TOFIX: plumbum?
        # TODO: also in init!

        # images pull
        command.append('pull')
        # log.pp(self._vanilla_services)
        # log.pp(self._compose_project)

        raise NotImplementedAction("Missing recursion on service links")

        for service in self._compose_project.services:
            if service.name not in self._vanilla_services:
                continue
            # recursion on links
            for link in service.links:
                linked_service, name = link
                print("TEST 2", linked_service)
            # log.pp(service.__dict__)
            command.append(service)
        self._exec(command)

        # bower/npm/yarn install

        raise NotImplementedAction(
            'pull git, docker images and bower libs in blueprint %s' % project
        )

    def do_start(self, command, action, service, **kwargs):
        self.service_mandatory(service)
        self._exec("%s %s %s" % (command, action, service))

    def do_stop(self, command, action, service, **kwargs):
        self.service_mandatory(service)
        self._exec("%s %s %s" % (command, action, service))

    def do_restart(self, command, action, service, **kwargs):
        self.service_mandatory(service)
        self._exec("%s %s %s" % (command, action, service))

    def do_graceful(self, command, action, service, **kwargs):
        self.service_mandatory(service)
        self._exec("%s %s %s" % (command, action, service))

    def do_scale(self, command, action, service, num, **kwargs):
        self.service_mandatory(service)
        self._exec(
            "%s %s %s=%s" % (command, action, service, num))

    def do_logs(self, command, action, service, **kwargs):
        if service is None:
            self._exec("%s %s" % (command, action))
        else:
            self._exec("%s %s %s" % (command, action, service))

    def do_remove(self, command, action, service, **kwargs):
        # service is required or not for this action?
        self.service_mandatory(service)
        self._exec("%s %s %s" % (command, action, service))

    def do_clean(self, command, action, service, **kwargs):
        # service is required or not for this action?
        self.service_mandatory(service)
        self._exec("%s %s %s" % (command, action, service))

    def do_command(self, command, action, service, arguments, **kwargs):
        self.service_mandatory(service)
        if len(arguments) == 0:
            raise InvalidArgument('Missing arguments for command action')

        self._exec(
            "%s exec %s %s" % (command, service, arguments))

    def do_shell(self, command, action, service, **kwargs):
        self.service_mandatory(service)
        self.do_command(
            command, action, service, arguments='bash')

    def do_bower(self, command, action, service, arguments, **kwargs):
        self.service_incompatible(service)
        if len(arguments) == 0:
            raise InvalidArgument('Missing arguments for bower action')

        self.do_command(
            command, action, service='bower', arguments=arguments)
