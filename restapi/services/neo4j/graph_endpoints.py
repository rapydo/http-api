# -*- coding: utf-8 -*-

from restapi.rest.definition import EndpointResource

from restapi.utilities.logs import log

log.warning("This class is deprecated, stop using it as endpoint parent")


class GraphBaseOperations(EndpointResource):

    pass
