from typing import Any, Callable, Dict, Optional, Tuple, TypeVar, Union

from flask import Response as FlaskResponse
from werkzeug.wrappers import Response as WerkzeugResponse

Response = Union[FlaskResponse, WerkzeugResponse, Tuple[Any, int, Dict[str, str]]]
ResponseContent = Optional[Any]
Props = Dict[str, Any]
FlaskRequest = Any
# instead of ... should be [EndpointResource, anything else]
# but mypy only allows to specify all or none input parameters
EndpointFunction = TypeVar("EndpointFunction", bound=Callable[..., Response])
