"""
Handling IDs in a more secure way
"""

import uuid


def getUUID():
    return str(uuid.uuid4())
