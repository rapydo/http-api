#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TODO: use log from rapydo.utils when packaged

import signal
import sys
import time


def signal_term_handler(signal=None, frame=None, name='SIGTERM'):
    # print("TEST", signal, frame)
    print(f"got {name}")
    sys.exit(0)


signal.signal(signal.SIGTERM, signal_term_handler)

# infinity = int(float("inf"))  # does not work
low_infinity = sys.maxsize / 10000000000

try:
    print("Sleeping in python")
    time.sleep(low_infinity)
except KeyboardInterrupt:
    signal_term_handler(name='keyboard interrupt')
