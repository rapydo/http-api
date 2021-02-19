import os
import sys
import time

import click
from flask.cli import FlaskGroup

from restapi import __package__ as current_package
from restapi.config import CUSTOM_PACKAGE, PRODUCTION
from restapi.connectors import Connector
from restapi.env import Env
from restapi.utilities import print_and_exit
from restapi.utilities.logs import log
from restapi.utilities.processes import find_process, wait_socket

BIND_INTERFACE = "0.0.0.0"


@click.group()
def cli():  # pragma: no cover
    click.echo("*** RESTful HTTP API ***")


# Too dangerous to launch it during tests... skipping tests
def main(args):  # pragma: no cover

    current_app = os.getenv("FLASK_APP")
    if current_app is None or current_app.strip() == "":
        os.environ["FLASK_APP"] = f"{current_package}.__main__"

    fg_cli = FlaskGroup()
    options = {"prog_name": "restapi", "args": args}

    # cannot catch for CTRL+c
    fg_cli.main(**options)


def initializing():

    return find_process(current_package, keywords=["init"], prefix="/usr/local/bin/")


# Too dangerous to launch it during tests... skipping tests
@cli.command()
def launch():  # pragma: no cover
    """Launch the RAPyDo-based HTTP API server"""

    mywait()

    args = [
        "run",
        "--host",
        BIND_INTERFACE,
        "--port",
        os.getenv("FLASK_PORT"),
        "--reload",
        "--no-debugger",
        "--eager-loading",
        "--with-threads",
    ]

    if initializing():
        print_and_exit(
            "Please wait few more seconds: initialization is still in progress"
        )
    else:
        main(args)
        log.warning("Server shutdown")


# Multiple is not used, should be removed by fixing verify command
@cli.command()
@click.option("--services", "-s", multiple=True, default=[])
def verify(services):
    """Verify connected service"""

    if len(services) == 0:
        log.warning("Empty list of services, nothing to be verified.")
        log.info("Provide list of services by using --services option")

    for service in services:

        if not Connector.check_availability(service):
            print_and_exit("Service {} not detected", service)

        log.info("Verifying service: {}", service)
        variables = Connector.services.get(service, {})
        host, port = get_service_address(variables, "host", "port", service)
        wait_socket(host, port, service)

    log.info("Completed successfully")


@cli.command()
@click.option(
    "--wait/--no-wait",
    default=False,
    help="Wait for services availability before starting the initialization",
)
@click.option(
    "--force-user/--no-force-user",
    default=False,
    help="Force the creation of default user",
)
@click.option(
    "--force-group/--no-force-group",
    default=False,
    help="Force the creation of default group",
)
def init(wait, force_user, force_group):
    """Initialize data for connected services"""
    if wait:
        mywait()

    from restapi.server import ServerModes, create_app

    log.info("Launching initialization app")

    options = {
        "force_user": force_user,
        "force_group": force_group,
    }
    create_app(name="Initializing services", mode=ServerModes.INIT, options=options)

    log.info("Initialization requested")


@cli.command()
def wait():
    """Wait critical service(s) startup"""
    mywait()


def get_service_address(variables, host_var, port_var, service):

    host = variables.get(host_var)
    if host is None:
        print_and_exit("Cannot find any variable matching {} for {}", host_var, service)

    port = variables.get(port_var)
    if port is None:
        print_and_exit("Cannot find any variable matching {} for {}", port_var, service)

    log.info("Connecting to {} ({}:{})...", service, host, port)

    return host, int(port)


def mywait():
    """
    Wait for a service on his host:port configuration
    basing the check on a socket connection.
    """
    for name, variables in Connector.services.items():

        if name == "smtp":
            continue

        if name == "celery":

            broker = variables.get("broker", "N/A")

            if broker == "RABBIT":
                service_vars = Env.load_variables_group(prefix="rabbitmq")
            elif broker == "REDIS":
                service_vars = Env.load_variables_group(prefix="redis")
            else:
                print_and_exit("Invalid celery broker: {}", broker)  # pragma: no cover

            label = f"{broker.lower()} as celery broker"
            host, port = get_service_address(service_vars, "host", "port", label)

            wait_socket(host, port, label)

            backend = variables.get("backend", "N/a")
            # Rabbit is no longer used as backend due to the strong limitations
            if backend == "RABBIT":  # pragma: no cover
                service_vars = Env.load_variables_group(prefix="rabbitmq")
            elif backend == "REDIS":
                service_vars = Env.load_variables_group(prefix="redis")
            elif backend == "MONGODB":
                service_vars = Env.load_variables_group(prefix="mongo")
            else:
                print_and_exit(
                    "Invalid celery backend: {}", backend
                )  # pragma: no cover

            label = f"{backend.lower()} as celery backend"
            host, port = get_service_address(service_vars, "host", "port", label)

            wait_socket(host, port, label)

        else:
            host, port = get_service_address(variables, "host", "port", name)

            wait_socket(host, port, name)


# Too dangerous to launch it during tests... skipping tests
@cli.command()
@click.confirmation_option(help="Are you sure you want to drop data?")
def clean():  # pragma: no cover
    """Destroy current services data"""

    from restapi.server import ServerModes, create_app

    log.info("Launching destruction app")

    create_app(name="Removing data", mode=ServerModes.DESTROY)

    log.info("Destruction completed")


@cli.command()
def forced_clean():  # pragma: no cover
    """DANGEROUS: Destroy current data without asking yes/no """

    from restapi.server import ServerModes, create_app

    log.info("Launching destruction app")

    create_app(name="Removing data", mode=ServerModes.DESTROY)

    log.info("Destruction completed")


@cli.command()
@click.option("--wait/--no-wait", default=False, help="Wait for startup to finish")
@click.option(
    "--core/--no-core", default=False, help="Test for core instead of vanilla code"
)
@click.option("--file", default=None, help="Test a single file of tests")
@click.option("--folder", default=None, help="Test a single folder of tests")
@click.option(
    "--destroy/--no-destroy", default=False, help="Destroy database after tests"
)
def tests(wait, core, file, folder, destroy):  # pragma: no cover
    """Compute tests and coverage"""

    if wait:
        while initializing():
            log.debug("Waiting services initialization")
            time.sleep(5)
        mywait()

    num_opt = 0
    if core:
        num_opt += 1
    if file is not None:
        num_opt += 1
    if folder is not None:
        num_opt += 1

    if num_opt > 1:
        print_and_exit(
            "Please specify only one option between --core, --file and --folder"
        )

    parameters = ["tests/tests.sh"]
    if core:
        parameters.append(current_package)
    else:
        parameters.append(CUSTOM_PACKAGE)

    if file is not None:
        # Can't be enabled due to mistral stuck at py38
        # file = file.removeprefix("tests/")
        if file.startswith("tests/"):
            file = file[6:]

        if not os.path.isfile(os.path.join("tests", file)):
            print_and_exit("File not found: {}", file)
        parameters.append(file)
    elif folder is not None:
        if not os.path.isdir(os.path.join("tests", folder)):
            print_and_exit("Folder not found: {}", folder)
        parameters.append(folder)

    os.environ["TEST_CORE_ENABLED"] = str(core)
    # In prod mode tests are execute with the server running.
    # Destroy test fails with alchemy due to db locks
    if destroy and not PRODUCTION:
        os.environ["TEST_DESTROY_MODE"] = "1"
    try:

        log.info("Running tests... this may take some time")
        log.debug("Executing: {}", parameters)
        from plumbum import local

        command = local["bash"]
        command(parameters, stdout=sys.stdout, stderr=sys.stderr)
        sys.exit(0)

    except Exception as e:
        log.error(e)
        sys.exit(1)


@cli.command()
def bot():
    # as is required to prevent name collision with the function bot()
    from restapi.services.telegram import bot as telegram_bot

    telegram_bot.load_commands()
    # This return is used by tests to verify output messages
    return telegram_bot.start()


@cli.command()
def clearcache():
    from restapi.server import create_app
    from restapi.services.cache import Cache

    create_app(name="Cache clearing")

    Cache.clear()

    log.info("Cache cleared")
