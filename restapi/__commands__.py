# -*- coding: utf-8 -*-

import os
import time
import click
import better_exceptions as be
from flask.cli import FlaskGroup
from utilities.logs import get_logger
from utilities.processes import wait_socket
from restapi import __package__ as current_package

APP = 'FLASK_APP'
PORT = 'FLASK_PORT'

log = get_logger(__name__)


@click.group()
# @click.option('--debug/--no-debug', default=False)
# def cli(debug):
def cli():
    # click.echo('Debug mode is %s' % ('on' if debug else 'off'))
    click.echo('*** RESTful HTTP API ***')


def main(args, another_app=None):

    if another_app is not None:
        os.environ[APP] = '%s.py' % another_app
    else:
        current_app = os.environ.get(APP)
        if current_app is None or current_app.strip() == '':
            os.environ[APP] = '%s.__main__' % current_package

    cli = FlaskGroup()
    options = {
        'prog_name': 'restapi',
        'args': args,
    }

    # cannot catch for CTRL+c
    cli.main(**options)

    # try:
    #     cli.main(**options)
    # except SystemExit as e:
    #     if str(e) == "3":
    #         print("AH!")
    #     else:
    #         # it looks like there is no Keyboard interrupt with flask
    #         log.warning("Flask received: system exit")
    # except BaseException as e:
    #     # do not let flask close the application
    #     # so we can do more code after closing
    #     log.error(e)
    #     log.warning('error type: %s' % type(e))


def flask_cli(options=None):
    log.info("Launching the app")
    from restapi.server import create_app
    # log.warning("TEST")
    if options is None:
        options = {'name': 'RESTful HTTP API server'}
        app = create_app(**options)
        app.run(host='0.0.0.0', threaded=True)
    else:
        create_app(**options)
        # app.run(debug=False)
    log.warning("Completed")


def starting_up():
    from utilities import processes
    return processes.find(
        current_package,
        suffixes=['wait', 'init'],
        local_bin=True
    )


@cli.command()
# @click.option(
#     '--wait/--no-wait', default=False, help='Wait for startup to finish')
# def launch(wait):
def launch():
    """Launch the RAPyDo-based HTTP API server"""
    args = [
        'run',
        '--host', '0.0.0.0',
        '--port', os.environ.get(PORT),
        '--reload',
        '--no-debugger',
        '--eager-loading',
        '--with-threads'
    ]

    if starting_up():
        log.exit("Please wait few more seconds: resources still starting up")
    else:
        main(args)
        log.warning("Server shutdown")


@cli.command()
@click.option('--services', '-s', multiple=True, default=['postgres'])
def verify(services):
    """Verify connected service"""
    from restapi.services.detect import detector

    for service in services:
        myclass = detector.services_classes.get(service)
        if myclass is None:
            log.exit("Service \"%s\" was NOT detected" % service)
        log.info("Verifying service: %s", service)
        host, port = get_service_address(
            myclass.variables, 'host', 'port', service)
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
    # if host is None:
    #     log.warning("Unable to find HOST variable for %s", service)
    #     for k in myclass.variables:
    #         log.critical(myclass.variables)
    #         if k.endswith("_host"):
    #             host = myclass.variables.get(k)
    #             log.info("Using %s as HOST variable for %s", k, service)
    if host is None:
        log.exit(
            "Cannot find any variable matching %s for %s", host_var, service)

    port = variables.get(port_var)
    # if port is None:
    #     log.warning("Unable to find PORT variable for %s", service)
    #     for k in myclass.variables:
    #         if k.endswith("_port"):
    #             port = myclass.variables.get(k)
    #             log.info("Using %s as PORT variable for %s", k, service)

    if port is None:
        log.exit(
            "Cannot find any variable matching %s  for %s", port_var, service)

    log.debug("Checking address: %s:%s", host, port)

    return host, int(port)


def mywait():
    """
    Wait for a service on his host:port configuration
    basing the check on a socket connection.

    NOTE: this could be packaged as a `waiter` cli utility probably
    p.s. could that be done with rapydo-utils maybe?
    pp.ss. could rapydo utils be python 2.7+ compliant?
    """
    from restapi.services.detect import detector

    for name, myclass in detector.services_classes.items():

        if name == 'authentication':
            continue

        if name == 'celery':
            host, port = get_service_address(
                myclass.variables, 'broker_host', 'broker_port', name)

            wait_socket(host, port, name)

            host, port = get_service_address(
                myclass.variables, 'backend_host', 'backend_port', name)

            wait_socket(host, port, name)
        else:
            host, port = get_service_address(
                myclass.variables, 'host', 'port', name)

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
@click.option(
    '--wait/--no-wait', default=False, help='Wait for startup to finish')
@click.option(
    '--core/--no-core', default=False,
    help='Test for core instead of vanilla code')
def tests(wait, core):
    """Compute tests and coverage"""

    if wait:
        while starting_up():
            log.debug('Waiting service startup')
            time.sleep(5)

    log.debug("Starting unit tests: %s", be)

    # launch unittests and also compute coverage
    # TODO: convert the `pyunittests` script from the docker image into python
    from utilities.basher import BashCommands
    bash = BashCommands()
    log.warning(
        "Running all tests and computing coverage.\n" +
        "This might take some minutes."
    )

    # FIXME: does not work
    # use the 'template' dir found in /code
    parameters = []
    # from utilities import helpers
    # basedir = helpers.latest_dir(helpers.current_fullpath())
    if core:
        parameters.append(current_package)
    # import glob
    # if 'template' in glob.glob('*'):
    #     from restapi import __package__ as current_package
    #     parameters.append(current_package)

    output = bash.execute_command(
        "pyunittests",
        parameters=parameters, catchException=True, error_max_len=-1)

    log.info("Completed:\n%s", output)
