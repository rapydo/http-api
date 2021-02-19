import errno
import math
import os
import signal
import socket
import time
from datetime import datetime

import psutil

from restapi.config import TESTING
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log

DEFAULT_MAX_RETRIES = 999 if not TESTING else 30


class Timeout(Exception):
    pass


def handler(signum, frame):
    raise Timeout("Operation timeout: interrupted")


def start_timeout(time):
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(time)


def stop_timeout():
    signal.alarm(0)


def find_process(process_name, keywords=None, prefix=None):

    if keywords is None:
        keywords = []

    if prefix:
        keywords.append(f"{prefix}{process_name}")

    current_pid = os.getpid()

    for pid in psutil.pids():

        if pid == current_pid or not psutil.pid_exists(pid):
            continue  # pragma: no cover
        process = psutil.Process(pid)

        if process.name() != process_name:
            continue
        cmd = process.cmdline()

        if not all(elem in cmd for elem in keywords):
            continue

        cmdline = " ".join(cmd)
        d = datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S")
        log.warning(
            "Process is running\nPID: {}\nCreated: {}\nCmd: {}", pid, d, cmdline
        )
        return True

    return False


def wait_socket(host, port, service_name, retries=DEFAULT_MAX_RETRIES):

    SLEEP_TIME = 2
    TIMEOUT = 1

    log.debug("Waiting for {} ({}:{})", service_name, host, port)

    counter = 0
    begin = time.time()
    while True:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.settimeout(TIMEOUT)

            try:
                result = s.connect_ex((host, port))
            except socket.gaierror:
                result = errno.ESRCH

            if result == 0:
                log.info("Service {} is reachable", service_name)
                break

            counter += 1

            if counter >= retries:
                t = math.ceil(time.time() - begin)
                raise ServiceUnavailable(
                    f"{service_name} ({host}:{port}) unavailable after {t} seconds"
                )

            if counter % 15 == 0:  # pragma: no cover
                log.warning(
                    "{} ({}:{}) is still unavailable after {} seconds",
                    service_name,
                    host,
                    port,
                    math.ceil(time.time() - begin),
                )
            else:
                log.debug("{} ({}:{}) not reachable", service_name, host, port)

            time.sleep(SLEEP_TIME)
