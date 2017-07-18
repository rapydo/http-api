# -*- coding: utf-8 -*-

import os
# import time
import click
from flask.cli import FlaskGroup
from utilities.logs import get_logger

APP = 'FLASK_APP'
PORT = 'FLASK_PORT'
log = get_logger('COMMANDER')


@click.group()
@click.option('--debug/--no-debug', default=False)
def cli(debug):
    click.echo('Debug mode is %s' % ('on' if debug else 'off'))


def main(args, another_app=None):

    if another_app is not None:
        os.environ[APP] = '%s.py' % another_app
    else:
        current_app = os.environ.get(APP)
        if current_app is None or current_app.strip() == '':
            from restapi import __package__ as current_package
            os.environ[APP] = '%s.__main__' % current_package

    cli = FlaskGroup()
    options = {
        'prog_name': 'restapi',
        'args': args,
    }
    cli.main(**options)


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
    log.warning("Server requested to shutdown")


@cli.command()
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
    main(args)
    log.warning("Server requested to shutdown")


@cli.command()
@click.option('--wait/--no-wait', default=False)
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


def mywait():

    from restapi.services.detect import detector
    service = detector.authentication_service
    log.info("Waiting for authentication service: %s" % service)

    myclass = detector.services_classes.get(service)
    host = myclass.variables.get('host')
    port = int(myclass.variables.get('port'))
    log.debug("Socket %s:%s" % (host, port))

    import socket
    import errno
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            result = s.connect_ex((host, port))
        except socket.gaierror:
            result = errno.ESRCH

        if result == 0:
            log.info("Service %s is reachable" % service)
            break
        else:
            log.debug("Not reachable yet")  # :\n%s" % errno.errorcode[result])
            import time
            time.sleep(2)


@cli.command()
def clean():
    """Destroy current services data"""
    flask_cli({'name': 'Removing data', 'destroy_mode': True})


@cli.command()
def unittests():
    """Compute tests and coverage"""

    # launch unittests and also compute coverage
    # TODO: convert the `pyunittests` script from the docker image into python
    from utilities.basher import BashCommands
    bash = BashCommands()
    log.warning(
        "Running all tests and computing coverage.\n" +
        "This might take some minutes."
    )

    # NOTE: running tests on a generic backend
    # if the current directory is '/code'
    parameters = []
    from utilities import helpers
    basedir = helpers.latest_dir(helpers.current_fullpath())
    if basedir == 'code':
        from restapi import __package__ as current_package
        parameters.append(current_package)

    output = bash.execute_command(
        "pyunittests",
        parameters=parameters
    )

    log.info("Completed:\n%s" % output)


# TODO: evaluate what to do with the sleep script
# @cli.command()
# def sleep():
#     # put it in here?
#     # or create a pypi package?
#     pass
