# -*- coding: utf-8 -*-

import sys

__version__ = '0.6.2'

FRAMEWORK_NAME = 'RAPyDo'
FRAMEWORK_PREFIX = FRAMEWORK_NAME.lower() + '-'

# detect if the developer is asking for help/usage on the cli command
# 1. if using the help option
# 2. if giving no commands
# 3. watch out when the only arg is uwsgi

if '--help' in sys.argv:
    FLASK_HELP = True
elif len(sys.argv) > 1:
    FLASK_HELP = False
elif len(sys.argv) == 1 and sys.argv[0].endswith('uwsgi'):
    FLASK_HELP = False
else:
    FLASK_HELP = True
