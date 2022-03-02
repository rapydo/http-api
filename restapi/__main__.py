#!/usr/bin/env python
from restapi.config import MAIN_SERVER_NAME
from restapi.server import create_app

app = create_app(name="REST_API")

if __name__ == MAIN_SERVER_NAME:
    app.run(host="0.0.0.0", threaded=True)
