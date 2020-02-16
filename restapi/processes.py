# -*- coding: utf-8 -*-

import os
import psutil
from restapi.utilities.logs import log


def find(prefix, suffixes=None, local_bin=False):

    current_pid = os.getpid()

    for pid in psutil.pids():

        if pid == current_pid or not psutil.pid_exists(pid):
            continue
        process = psutil.Process(pid)

        if process.name() == prefix:
            cmd = process.cmdline()

            if local_bin:
                check = False
                for word in cmd:
                    if '/usr/local/bin' in word:
                        check = True
                if not check:
                    continue

            if suffixes is not None:
                check = False
                for word in cmd:
                    if word in suffixes:
                        check = True
                if not check:
                    continue

            log.warning('Already existing')
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
