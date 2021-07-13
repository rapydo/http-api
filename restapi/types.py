from typing import Any, Dict, Optional, Tuple, Union

from flask import Response as FlaskResponse

Response = Union[FlaskResponse, Tuple[Any, int, Dict[str, str]]]
ResponseContent = Optional[Any]
Props = Dict[str, Any]
FlaskRequest = Any
