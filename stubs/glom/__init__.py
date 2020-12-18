from typing import Any, Dict


class Spec:
    # Glom is not really intended to return a str, but it is true in my case
    def glom(self, target: Dict[str, Any], **kw: str) -> str:
        ...
