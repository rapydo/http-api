"""
### HTTP status codes ===
http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html

Should take a look here also:
http://www.restapitutorial.com/httpstatuscodes.html
http://racksburg.com/choosing-an-http-status-code/

"""

from restapi.utilities.logs import log

# Deprecated since 0.9
log.warning("Deprecated use of hcodes")


class hcodes:

    # RESPONSE RECEIVED
    HTTP_OK_BASIC = 200
    HTTP_OK_CREATED = 201
    HTTP_OK_ACCEPTED = 202

    # SOFTWARE ERROR
    HTTP_BAD_REQUEST = 400
    HTTP_BAD_UNAUTHORIZED = 401
    HTTP_BAD_FORBIDDEN = 403
    HTTP_BAD_NOTFOUND = 404
    HTTP_BAD_CONFLICT = 409

    # SERVER ERROR
    HTTP_SERVER_ERROR = 500
    HTTP_SERVICE_UNAVAILABLE = 503
