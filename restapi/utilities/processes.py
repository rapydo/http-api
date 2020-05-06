# -*- coding: utf-8 -*-

import os
import psutil
from datetime import datetime
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
        d = datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S")
        log.warning(
            'Process is running\nPID: {}\nCreated: {}\nCmd: {}',
            pid, d, cmdline
        )
        return True

    return False


def wait_socket(host, port, service_name):

    import time
    import errno
    import socket

    sleep_time = 2
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
            if counter % 15 == 0:
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
