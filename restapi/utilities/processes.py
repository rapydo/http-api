# -*- coding: utf-8 -*-

import os
import psutil
from restapi.utilities.logs import log


def find_process(process_name, keywords=None, prefix=None):

    if keywords is None:
        keywords = []

    if prefix:
        keywords.append("{}{}".format(prefix, process_name))

    current_pid = os.getpid()

    for pid in psutil.pids():

        if pid == current_pid or not psutil.pid_exists(pid):
            continue
        process = psutil.Process(pid)

        if process.name() != process_name:
            continue
        cmd = process.cmdline()

        if not all(elem in cmd for elem in keywords):
            continue

        cmdline = ' '.join(cmd)
        log.warning('Process {} is running with PID {}', cmdline, pid)
        return True

    return False


def wait_socket(host, port, service_name):

    import time
    import errno
    import socket

    sleep_time = 1
    timeout = 1

    log.verbose("Waiting for {} ({}:{})", service_name, host, port)

    counter = 0
    while True:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.settimeout(timeout)

            try:
                result = s.connect_ex((host, port))
            except socket.gaierror:
                result = errno.ESRCH

            if result == 0:
                log.info("Service {} is reachable", service_name)
                break

            counter += 1
            if counter % 20 == 0:
                log.warning(
                    "'{}' service ({}:{}) still unavailable after {} seconds",
                    service_name,
                    host,
                    port,
                    (sleep_time + timeout) * counter,
                )
            else:
                log.debug("Not reachable yet: {} ({}:{})", service_name, host, port)

            time.sleep(sleep_time)
