# -*- coding: utf-8 -*-

import argparse
import os
import sys

from do_actions import InvalidArgument, NotImplementedAction
try:
    from ..do_actions import CustomActions as ImplementedActions
    print("\nYou are using a custom implementation for actions")
except Exception as e:
    from do_actions import ImplementedActions
    print("\nYou are using the base implementation for actions")

#####################################
# Configuration
INFO = "\033[1;32mINFO\033[1;0m"
WARNING = "\033[1;33mWARNING\033[1;0m"
ERROR = "\033[1;31mERROR\033[1;0m"

CONTAINER_DIR = "../containers"
BASE_YAML = "containers.yml"
backend_yaml_path = "docker-compose.yml"
frontend_yaml_path = "../frontend/docker-compose.yml"

compose_project = None


#####################################
def myprint(level, message):
    print("%s: %s" % (level, message))


def list_all_projects():
    myprint(
        INFO, "List of available projects as found in **%s**" % CONTAINER_DIR)
    projects = os.listdir(CONTAINER_DIR)
    projects.sort()
    num = 0
    for p in projects:
        project_path = os.path.join(CONTAINER_DIR, p)
        if not os.path.isdir(project_path):
            continue
        myprint(INFO, "\t- %s" % p)
        num += 1

    if num == 0:
        myprint(WARNING, "\t- None")


def list_all_modes(project, project_path):
    myprint(INFO, "List of available modes in project **%s**" % project)

    modes = os.listdir(project_path)
    modes.sort()
    num = 0
    for m in modes:
        mode_path = os.path.join(project_path, m)
        if os.path.isdir(mode_path):
            continue
        if not m.endswith(".yml"):
            continue

        myprint(INFO, "\t- %s" % m[0:-4])
        num += 1

    if num == 0:
        myprint(WARNING, "\t- None")


def read_services_from_compose_yaml(file):
    from compose.config import config
    out = config.load_yaml(file)
    # from beeprint import pp
    # pp(out)
    return out


def load_frontend(file):
    services = read_services_from_compose_yaml(file)
    return 'frontend' in services


def read_compose_project(config):
    from compose.cli.main import TopLevelCommand
    from compose.cli.command import project_from_options
    from compose.cli.docopt_command import DocoptDispatcher
    # import compose.cli.errors as errors

    dispatcher = DocoptDispatcher(
        TopLevelCommand, {'options_first': True, 'version': '1.8.0'})
    cli_options = config + ['config']
    options, handler, command_options = dispatcher.parse(cli_options)
    project = project_from_options('.', options)
    return project


def list_all_services():

    print("")
    myprint(INFO, "Services available:")
    print("")

    for service in compose_project.services:
        # print(service, type(service), service.__dict__)
        print(service.name)
    print("")


# ############################################ #

# Arguments definition
parser = argparse.ArgumentParser(
    prog='do',
    description='Do things on this project'
)

parser.add_argument('--project', type=str, metavar='p',
                    help='Current project')
parser.add_argument('--mode', type=str, metavar='m',
                    help='Mode to be executed')
parser.add_argument('--list', action='store_true',
                    help='Docker compose service')
parser.add_argument('--action', type=str, metavar='a',
                    help='Desired action')
parser.add_argument('--service', type=str, metavar='s',
                    help='Docker compose service')
parser.add_argument('--workers', type=int, metavar='w',
                    help='Number of celery workers to be executed')
parser.add_argument('extra_arguments',
                    help='Extra arguments for bower and command actions',
                    nargs='*')

# Reading input parameters
args = parser.parse_args()

args = vars(args)

project = args['project']
mode = args['mode']
list_services = args['list']
action = args['action']
service = args['service']
num_workers = args['workers']
extra_arguments = args['extra_arguments']

if extra_arguments is not None:
    extra_arguments = ' '.join(extra_arguments)

# Implemented actions are automatically parsed by the ImplementedActions class
# all do_something methods are interpreted as 'something' actions
actions = []
for x in sorted(dir(ImplementedActions)):
    if x.startswith("do_"):
        actions.append(x[3:])

try:
    # List of available projects, when a project is not specified
    # Projects are directories into the CONTAINER_DIR
    if project is None:
        list_all_projects()
        sys.exit(0)

    project_path = os.path.join(CONTAINER_DIR, project)
    if not os.path.isdir(project_path):
        raise InvalidArgument("Project not found (%s)" % project_path)

    myprint(INFO, "You selected project: \t%s" % project)

    # List of available modes, when a mode is not specified
    # Modes are .yml files into the CONTAINER_DIR/project dir
    if mode is None:
        list_all_modes(project, project_path)
        sys.exit(0)

    # The specified mode doesn't exist
    mode_path = os.path.join(project_path, mode) + ".yml"
    if not os.path.isfile(mode_path):
        raise InvalidArgument("Mode not found (%s)" % mode_path)
    myprint(INFO, "You selected mode: \t%s" % mode)

    # Load project from docker-compose
    command_prefix = []
    command_prefix.append('-f')
    command_prefix.append(backend_yaml_path)
    if load_frontend(mode_path):
        command_prefix.append('-f')
        command_prefix.append(frontend_yaml_path)
    command_prefix.append('-f')
    command_prefix.append(mode_path)
    compose_project = read_compose_project(command_prefix)

    # List of available services obtained from the specified /project/mode.yml
    if list_services:
        list_all_services()
        sys.exit(0)

    if action == 'scale':
        raise InvalidArgument(
            'Use parameter --workers instad of --action scale')

    if num_workers is not None:
        action = 'scale'

    if action is None or action not in actions:
        raise InvalidArgument(
            "You should specify a valid action.\n" +
            "Available actions:\n\t%s" % actions
        )

    if num_workers is not None:
        myprint(INFO, "You selected action: \t%s=%s" % (action, num_workers))
    elif extra_arguments is not None:
        myprint(INFO, "You selected action: \t%s %s" %
                (action, extra_arguments))
    else:
        myprint(INFO, "You selected action: \t%s" % action)

    try:
        implemented = ImplementedActions(
            compose_project,
            read_services_from_compose_yaml(mode_path)
        )
        func = getattr(ImplementedActions, 'do_%s' % action)
        # import inspect
        # argspec = inspect.getargspec(func)
        func_args = {
            'self': implemented,
            'command': command_prefix,
            'project': project,
            'mode': mode,
            'action': action,
            'service': service,
            'num': num_workers,
            'arguments': extra_arguments,
        }
        func(**func_args)

    except AttributeError as e:
        raise InvalidArgument('Method do_%s() not found' % action)

except InvalidArgument as e:
    myprint(ERROR, str(e))
    sys.exit(1)
except NotImplementedAction as e:
    myprint(WARNING, "NOT IMPLEMENTED: %s " % e)
    sys.exit(1)
