# -*- coding: utf-8 -*-

import click
import os
from flask.cli import FlaskGroup
from restapi import __package__ as current_package
from utilities.logs import get_logger

APP = 'FLASK_APP'
log = get_logger('COMMANDER')


def main(args, another_app=None):

    if another_app is not None:
        os.environ[APP] = '%s.py' % another_app
    else:
        current_app = os.environ.get(APP)
        if current_app is None or current_app.strip() == '':
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
        '--port', os.environ.get('FLASK_PORT'),
        '--reload',
        '--no-debugger',
        '--eager-loading',
        '--with-threads'
    ]
    main(args)


@click.command()
def init():
    """Initialize data for connected services."""
    cli({'name': 'Initializing services', 'init_mode': True})


@click.command()
def clean():
    """Destroy current services data."""
    cli({'name': 'Removing data', 'destroy_mode': True})
