"""
RAPyDo core module for HTTP Restful APIs
"""

import sys

__version__ = "3.0"

FLASK_HELP = len(sys.argv) <= 1 or "--help" in sys.argv
