# -*- coding: utf-8 -*-

import os
import time
import click
from flask.cli import FlaskGroup
from utilities.logs import get_logger

APP = 'FLASK_APP'
PORT = 'FLASK_PORT'
log = get_logger('COMMANDER')


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


def cli(options=None):
    """This is an example command."""

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


@click.command()
def launch():
    """Launch the RAPyDo-based HTTP API server."""
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


def myinit():
    cli({'name': 'Initializing services', 'init_mode': True})


@click.command()
@click.option('--sleep/--no-sleep', default=False)
def init(sleep):
    """Initialize data for connected services."""
    if sleep:
        # if request sleep some seconds to wait for db to be ready
        time.sleep(30)
    myinit()


@click.command()
def clean():
    """Destroy current services data."""
    cli({'name': 'Removing data', 'destroy_mode': True})


@click.command()
@click.option('--initialize/--no-initialize', default=False)
@click.option('--sleep/--no-sleep', default=False)
def unittests(initialize, sleep):
    """Launch tests and compute coverage for the current package"""

    # if request initialize the authorization database
    if initialize:
        # if request sleep some seconds to wait for db
        if sleep:
            time.sleep(30)
        # do init in a rapydo way
        myinit()

    # launch unittests and also compute coverage
    # TODO: convert the `pyunittests` script from the docker image into python
    from utilities.basher import BashCommands
    bash = BashCommands()
    log.warning(
        "Running all tests and computing coverage.\n" +
        "This might take some minutes."
    )

    # NOTE: running tests on a generic backend
    # if the current directory is 'core'
    parameters = []

    # FIXME: put this into helpers
    def current_fullpath(*suffixes):
        return os.path.join(os.getcwd(), *suffixes)

    def latest_dir(path):
        return next(reversed(list(os.path.split(path))))

    basedir = latest_dir(current_fullpath())
    # from utilities import helpers
    # basedir = helpers.parent_dir(helpers.current_fullpath())

    log.warning("TEST BASE DIR: %s" % basedir)
    if basedir == 'code':
        from restapi import __package__ as current_package
        parameters.append(current_package)

    output = bash.execute_command(
        "pyunittests",
        parameters=parameters
    )

    log.info("Completed:\n%s" % output)


# TODO: evaluate what to do with the sleep script
@click.command()
def sleep():
    """test 1"""
    # put it in here?
    # or create a pypi package?
    pass
