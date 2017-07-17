# -*- coding: utf-8 -*-

import sys

__version__ = '0.5.1'

FRAMEWORK_NAME = 'RAPyDo'
FRAMEWORK_PREFIX = FRAMEWORK_NAME.lower() + '-'

# detect if the developer is asking for help/usage on the cli command
# 1. if using the help option
# 2. if giving no commands
FLASK_HELP = \
    '--help' in sys.argv \
    or len(sys.argv) < 2
