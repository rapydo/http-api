import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click
from flask.cli import FlaskGroup

from restapi import __package__ as current_package
from restapi.config import BACKEND_PACKAGE, CUSTOM_PACKAGE, PRODUCTION
from restapi.connectors import Connector
from restapi.env import Env
from restapi.utilities import print_and_exit
from restapi.utilities.logs import log
from restapi.utilities.processes import find_process, wait_socket

BIND_INTERFACE = "0.0.0.0"


@click.group()
def cli() -> None:  # pragma: no cover
    click.echo("*** RESTful HTTP API ***")


# Too dangerous to launch it during tests... skipping tests
def main(args: List[str]) -> None:  # pragma: no cover

    current_app = Env.get("FLASK_APP", "").strip()
    if not current_app:
        os.environ["FLASK_APP"] = f"{current_package}.__main__"

    # Call to untyped function "FlaskGroup" in typed context
    fg_cli = FlaskGroup()  # type: ignore
    options = {"prog_name": "restapi", "args": args}

    # cannot catch for CTRL+c
    # Call to untyped function "main" in typed context
    fg_cli.main(**options)  # type: ignore


def initializing() -> bool:

    return find_process(current_package, keywords=["init"], prefix="/usr/local/bin/")


# Too dangerous to launch it during tests... skipping tests
@cli.command()
def launch() -> None:  # pragma: no cover
    """Launch the RAPyDo-based HTTP API server"""

    mywait()

    args = [
        "run",
        "--host",
        BIND_INTERFACE,
        "--port",
        Env.get("FLASK_PORT", "8080"),
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


@cli.command()
@click.option("--service", "-s")
def verify(service: str) -> None:
    """Verify if a service is connected"""

    if not Connector.check_availability(service):
        print_and_exit("Service {} not detected", service)

    log.info("Verifying service: {}", service)
    variables = Connector.services.get(service, {})
    host, port = get_service_address(variables, "host", "port", service)
    if host != "nohost":
        wait_socket(host, port, service)

    connector_module = Connector.get_module(service, BACKEND_PACKAGE)
    if not connector_module:  # pragma: no cover
        print_and_exit("Connector {} not detected", service)

    c = connector_module.get_instance()  # type: ignore
    log.info(
        "{} successfully authenticated on {}", service, c.variables.get("host", service)
    )
    # log.info("Completed successfully")


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
def init(wait: bool, force_user: bool, force_group: bool) -> None:
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
def wait() -> None:
    """Wait critical service(s) startup"""
    mywait()


def get_service_address(
    variables: Dict[str, str], host_var: str, port_var: str, service: str
) -> Tuple[str, int]:

    host = variables.get(host_var)
    if host is None:
        print_and_exit("Cannot find any variable matching {} for {}", host_var, service)

    port = variables.get(port_var)
    if port is None:
        print_and_exit("Cannot find any variable matching {} for {}", port_var, service)

    log.info("Connecting to {} ({}:{})...", service, host, port)

    return host, int(port)


def mywait() -> None:
    """
    Wait for a service on his host:port configuration
    basing the check on a socket connection.
    """
    for name, variables in Connector.services.items():

        if name == "smtp":
            log.info("Service {} is enabled but not tested at startup time", name)
            continue

        if name == "celery":

            broker = variables.get("broker_service", "N/A")

            if broker == "RABBIT":
                service_vars = Env.load_variables_group(prefix="rabbitmq")
            elif broker == "REDIS":
                service_vars = Env.load_variables_group(prefix="redis")
            else:
                print_and_exit("Invalid celery broker: {}", broker)  # pragma: no cover

            label = f"{broker.lower()} as celery broker"
            host, port = get_service_address(service_vars, "host", "port", label)

            wait_socket(host, port, label)

            backend = variables.get("backend_service", "N/a")
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

            if host != "nohost":
                wait_socket(host, port, name)


# Too dangerous to launch it during tests... skipping tests
@cli.command()
@click.confirmation_option(help="Are you sure you want to drop data?")
def clean() -> None:  # pragma: no cover
    """Destroy current services data"""

    from restapi.server import ServerModes, create_app

    log.info("Launching destruction app")

    create_app(name="Removing data", mode=ServerModes.DESTROY)

    log.info("Destruction completed")


@cli.command()
def forced_clean() -> None:  # pragma: no cover
    """DANGEROUS: Destroy current data without asking yes/no"""

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
def tests(
    wait: bool, core: bool, file: Optional[str], folder: Optional[str], destroy: bool
) -> None:  # pragma: no cover
    """Compute tests and coverage"""

    # Forced TEST mode when using the restapi tests wrapper
    os.environ["APP_MODE"] = "test"

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

    test_folder = Path("tests")
    if file is not None:

        filepath = Path(file)
        if test_folder not in filepath.parents:
            filepath = test_folder.joinpath(filepath)

        if not filepath.is_file():
            print_and_exit("File not found: {}", file)
        parameters.append(str(filepath.relative_to(test_folder)))
    elif folder is not None:

        folderpath = Path(folder)
        if test_folder not in folderpath.parents:
            folderpath = test_folder.joinpath(folderpath)

        if not folderpath.is_dir():
            print_and_exit("Folder not found: {}", folder)
        parameters.append(str(folderpath.relative_to(test_folder)))

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
        print_and_exit(str(e))


@cli.command()
def bot() -> None:
    # as is required to prevent name collision with the function bot()
    from restapi.services.telegram import bot as telegram_bot

    telegram_bot.load_commands()
    # This return is used by tests to verify output messages
    return telegram_bot.start()


@cli.command()
def clearcache() -> None:
    from restapi.server import create_app
    from restapi.services.cache import Cache

    create_app(name="Cache clearing")

    Cache.clear()

    log.info("Cache cleared")
