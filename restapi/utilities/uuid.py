"""
Handling IDs in a more secure way
"""

import uuid


def getUUID() -> str:
    return str(uuid.uuid4())
