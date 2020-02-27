# -*- coding: utf-8 -*-

import os
import time
import click
import pretty_errors
from flask.cli import FlaskGroup
from restapi.processes import wait_socket
from restapi import __package__ as current_package
from restapi.utilities.logs import log

BIND_INTERFACE = "0.0.0.0"


@click.group()
# @click.option('--debug/--no-debug', default=False)
# def cli(debug):
def cli():
    click.echo('*** RESTful HTTP API ***')


def main(args):

    current_app = os.environ.get('FLASK_APP')
    if current_app is None or current_app.strip() == '':
        os.environ['FLASK_APP'] = '{}.__main__'.format(current_package)

    fg_cli = FlaskGroup()
    options = {'prog_name': 'restapi', 'args': args}

    # cannot catch for CTRL+c
    fg_cli.main(**options)


def flask_cli(options=None):
    log.info("Launching the app")
    from restapi.server import create_app

    if options is None:
        options = {'name': 'RESTful HTTP API server'}
        app = create_app(**options)
        app.run(host=BIND_INTERFACE, threaded=True)
    else:
        create_app(**options)
    log.debug("cli execution completed")


def starting_up():
    from restapi.processes import find as find_process

    return find_process(current_package, suffixes=['wait', 'init'], local_bin=True)


@cli.command()
# @click.option(
#     '--wait/--no-wait', default=False, help='Wait for startup to finish')
# def launch(wait):
def launch():
    """Launch the RAPyDo-based HTTP API server"""
    args = [
        'run',
        '--host',
        BIND_INTERFACE,
        '--port',
        os.environ.get('FLASK_PORT'),
        '--reload',
        '--no-debugger',
        '--eager-loading',
        '--with-threads',
    ]

    if starting_up():
        log.exit("Please wait few more seconds: resources are still starting up")
    else:
        main(args)
        log.warning("Server shutdown")


@cli.command()
@click.option('--services', '-s', multiple=True, default=[])
def verify(services):
    """Verify connected service"""
    from restapi.services.detect import detector

    if len(services) == 0:
        log.warning("Empty list of services, nothing to be verified.")
        log.info("Provide list of services by using --services option")

    for service in services:
        myclass = detector.services_classes.get(service)
        if myclass is None:
            log.exit("Service \"{}\" was NOT detected", service)
        log.info("Verifying service: {}", service)
        host, port = get_service_address(myclass.variables, 'host', 'port', service)
        wait_socket(host, port, service)

    log.info("Completed successfully")


@cli.command()
@click.option('--wait/--no-wait', default=False, help='Wait for DBs to be up')
def init(wait):
    """Initialize data for connected services"""
    if wait:
        mywait()

    log.info("Initialization requested")
    flask_cli({'name': 'Initializing services', 'init_mode': True})


@cli.command()
def wait():
    """Wait critical service(s) startup"""
    mywait()


def get_service_address(variables, host_var, port_var, service):

    host = variables.get(host_var)
    if host is None:
        log.exit("Cannot find any variable matching {} for {}", host_var, service)

    port = variables.get(port_var)
    if port is None:
        log.exit("Cannot find any variable matching {} for {}", port_var, service)

    log.debug("Checking address: {}:{}", host, port)

    return host, int(port)


def mywait():
    """
    Wait for a service on his host:port configuration
    basing the check on a socket connection.
    """
    from restapi.services.detect import detector

    for name, myclass in detector.services_classes.items():

        if name == 'authentication':
            continue

        if name == 'celery':

            broker = myclass.variables.get('broker')

            if broker == 'RABBIT':
                service_vars = detector.load_variables({'prefix': 'rabbitmq'})
            elif broker == 'REDIS':
                service_vars = detector.load_variables({'prefix': 'redis'})
            else:
                log.exit("Invalid celery broker: {}", broker)

            host, port = get_service_address(service_vars, 'host', 'port', broker)

            wait_socket(host, port, broker)

            backend = myclass.variables.get('backend')
            if backend == 'RABBIT':
                service_vars = detector.load_variables({'prefix': 'rabbitmq'})
            elif backend == 'REDIS':
                service_vars = detector.load_variables({'prefix': 'redis'})
            elif backend == 'MONGODB':
                service_vars = detector.load_variables({'prefix': 'mongo'})
            else:
                log.exit("Invalid celery backend: {}", backend)

            host, port = get_service_address(service_vars, 'host', 'port', backend)

            wait_socket(host, port, backend)
        else:
            host, port = get_service_address(myclass.variables, 'host', 'port', name)

            wait_socket(host, port, name)


@cli.command()
@click.confirmation_option(help='Are you sure you want to drop data?')
def clean():
    """Destroy current services data"""
    flask_cli({'name': 'Removing data', 'destroy_mode': True})


@cli.command()
def forced_clean():
    """DANGEROUS: Destroy current data without asking yes/no """
    flask_cli({'name': 'Removing data', 'destroy_mode': True})


@cli.command()
@click.option('--wait/--no-wait', default=False, help='Wait for startup to finish')
@click.option(
    '--core/--no-core', default=False, help='Test for core instead of vanilla code'
)
@click.option('--file', default=None, help='Test a single file of tests')
@click.option('--folder', default=None, help='Test a single folder of tests')
def tests(wait, core, file, folder):
    """Compute tests and coverage"""

    if wait:
        while starting_up():
            log.debug('Waiting service startup')
            time.sleep(5)
        mywait()

    log.debug("Starting unit tests: {}", pretty_errors)

    # launch unittests and also compute coverage
    log.warning(
        "Running all tests and computing coverage.\n" + "This may take some minutes."
    )

    parameters = []
    if core:
        parameters.append(current_package)
    elif file is not None:
        if not os.path.isfile(os.path.join("tests", file)):
            log.exit("File not found: {}", file)
        else:
            parameters.append("default")
            parameters.append(file)
    elif folder is not None:
        if not os.path.isdir(os.path.join("tests", folder)):
            log.exit("Folder not found: {}", folder)
        else:
            parameters.append("default")
            parameters.append(folder)

    try:

        # TODO: convert the `pyunittests` script from the docker image into python
        # Pattern in plumbum library for executing a shell command
        from plumbum import local
        command = local["pyunittests"]
        log.verbose("Executing command pyunittests {}", parameters)
        output = command(parameters)

    except Exception as e:
        log.error(str(e))
        raise e

    log.info("Completed:\n{}", output)
