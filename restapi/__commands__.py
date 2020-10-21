import os
import sys
import time

import click
from flask.cli import FlaskGroup
from glom import glom

from restapi import __package__ as current_package
from restapi.confs import PRODUCTION
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


def flask_cli(options):
    log.info("Launching the app")
    from restapi.server import create_app

    create_app(**options)
    log.debug("cli execution completed")


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
        log.exit("Please wait few more seconds: initialization is still in progress")
    else:
        main(args)
        log.warning("Server shutdown")


@cli.command()
@click.option("--services", "-s", multiple=True, default=[])
def verify(services):
    """Verify connected service"""
    from restapi.services.detect import detector

    if len(services) == 0:
        log.warning("Empty list of services, nothing to be verified.")
        log.info("Provide list of services by using --services option")

    for service in services:

        myclass = glom(detector.services, f"{service}.class", default=None)
        if myclass is None:
            log.exit("Service {} not detected", service)
        log.info("Verifying service: {}", service)
        host, port = get_service_address(myclass.variables, "host", "port", service)
        wait_socket(host, port, service)

    log.info("Completed successfully")


@cli.command()
@click.option("--wait/--no-wait", default=False, help="Wait for DBs to be up")
def init(wait):
    """Initialize data for connected services"""
    if wait:
        mywait()

    log.info("Initialization requested")
    flask_cli({"name": "Initializing services", "init_mode": True})


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

    log.info("Connecting to {} ({}:{})...", service, host, port)

    return host, int(port)


def mywait():
    """
    Wait for a service on his host:port configuration
    basing the check on a socket connection.
    """
    from restapi.services.detect import detector

    for name, service in detector.services.items():

        myclass = service.get("class")
        if myclass is None:
            continue

        if name == "celery":

            broker = myclass.variables.get("broker")

            if broker == "RABBIT":
                service_vars = detector.load_variables(prefix="rabbitmq")
            elif broker == "REDIS":
                service_vars = detector.load_variables(prefix="redis")
            else:
                log.exit("Invalid celery broker: {}", broker)  # pragma: no cover

            host, port = get_service_address(service_vars, "host", "port", broker)

            wait_socket(host, port, broker)

            backend = myclass.variables.get("backend")
            if backend == "RABBIT":
                service_vars = detector.load_variables(prefix="rabbitmq")
            elif backend == "REDIS":
                service_vars = detector.load_variables(prefix="redis")
            elif backend == "MONGODB":
                service_vars = detector.load_variables(prefix="mongo")
            else:
                log.exit("Invalid celery backend: {}", backend)  # pragma: no cover

            host, port = get_service_address(service_vars, "host", "port", backend)

            wait_socket(host, port, backend)
        elif name == "smtp":
            pass

        else:
            host, port = get_service_address(myclass.variables, "host", "port", name)

            wait_socket(host, port, name)


# Too dangerous to launch it during tests... skipping tests
@cli.command()
@click.confirmation_option(help="Are you sure you want to drop data?")
def clean():  # pragma: no cover
    """Destroy current services data"""
    flask_cli({"name": "Removing data", "destroy_mode": True})


@cli.command()
def forced_clean():  # pragma: no cover
    """DANGEROUS: Destroy current data without asking yes/no """
    flask_cli({"name": "Removing data", "destroy_mode": True})


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
        log.exit("Please specify only one option between --core, --file and --folder")

    parameters = ["tests/tests.sh"]
    if core:
        parameters.append(current_package)
    elif file is not None:
        if file.startswith("tests/"):
            file = file[6:]

        if not os.path.isfile(os.path.join("tests", file)):
            log.exit("File not found: {}", file)
        parameters.append("default")
        parameters.append(file)
    elif folder is not None:
        if not os.path.isdir(os.path.join("tests", folder)):
            log.exit("Folder not found: {}", folder)
        parameters.append("default")
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
    from restapi.services.telegram import bot

    bot.load_commands()
    # This return is used by tests to verify output messages
    return bot.start()
