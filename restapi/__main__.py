#!/usr/bin/env python
from restapi.server import create_app

app = create_app(name="REST_API")

if __name__ == "__main__":
    app.run(host="0.0.0.0", threaded=True)
