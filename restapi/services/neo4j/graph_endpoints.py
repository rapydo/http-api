# -*- coding: utf-8 -*-

from restapi.rest.definition import EndpointResource

from restapi.utilities.logs import get_logger

log = get_logger(__name__)

log.warning("This class is deprecated, stop using it as endpoint parent")


class GraphBaseOperations(EndpointResource):

    pass
