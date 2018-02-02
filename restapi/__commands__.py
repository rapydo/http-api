# -*- coding: utf-8 -*-

import os
import time
import click
import better_exceptions as be
from flask.cli import FlaskGroup
from utilities.logs import get_logger
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


def wait_socket(host, port, service_name, sleep_time=1, timeout=5):

    import errno
    import socket

    log.verbose("Waiting for %s" % service_name)

    counter = 0
    while True:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # log.debug("Timeout before: %s", s.gettimeout())
        s.settimeout(timeout)
        # log.debug("Timeout after: %s", s.gettimeout())

        try:
            result = s.connect_ex((host, port))
        except socket.gaierror:
            result = errno.ESRCH

        if result == 0:
            log.info("Service %s is reachable", service_name)
            break
        else:

            counter += 1
            if counter % 5 == 0:
                # FIXME: also do something here if the service is external?
                log.warning(
                    "'%s' service looks still unavailable after %s seconds",
                    service_name, sleep_time * timeout * counter
                )
            else:
                log.debug("Not reachable yet: %s", service_name)

            time.sleep(sleep_time)


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

        host = myclass.variables.get('host')
        if host is None:
            log.warning("Unable to find HOST variable for %s", name)
            for k in myclass.variables:
                if k.endswith("_host"):
                    host = myclass.variables.get(k)
                    log.info("Using %s as HOST variable for %s", k, name)

        port = myclass.variables.get('port')
        if port is None:
            log.warning("Unable to find PORT variable for %s", name)
            for k in myclass.variables:
                if k.endswith("_port"):
                    port = myclass.variables.get(k)
                    log.info("Using %s as PORT variable for %s", k, name)

        if host is None:
            log.exit("Cannot find any variable matching a host for %s"% name)

        if port is None:
            log.exit("Cannot find any variable matching a port for %s"% name)

        log.debug("Socket %s:%s", host, port)

        # CHECK
        wait_socket(host, int(port), name)


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
