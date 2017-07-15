# -*- coding: utf-8 -*-

import os
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

    print("USING", os.environ.get(APP))

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
def init():
    """Initialize data for connected services."""
    myinit()


@click.command()
def clean():
    """Destroy current services data."""
    cli({'name': 'Removing data', 'destroy_mode': True})


# @click.command()
# def sleep():
#     """test 1"""
#     # TODO: evaluate what to do with the sleep script
#     # put it in here?
#     # or create a pypi package?
#     pass


@click.command()
@click.option('--initialize/--no-initialize', default=False)
# @click.option('--count', default=1, help='Number of greetings.')
# @click.option('--name', prompt='Your name', help='The person to greet.')
def unittests(initialize):
    """Launch tests and compute coverage for the current package"""

    if initialize:
        myinit()

    from utilities.basher import BashCommands
    bash = BashCommands()
    log.warning(
        "Running all tests and computing coverage.\n" +
        "This might take some minutes."
    )
    output = bash.execute_command("pyunittests")
    log.info("Completed:\n%s" % output)
