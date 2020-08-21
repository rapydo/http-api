from restapi.utilities.logs import log

_PUT = {
    "/stream/<channel>/<sync>": {
        "description": "Push to stream",
        "responses": {"200": {"description": "Message sent"}},
    }
}

v = vars()
for k in ("_GET", "_POST", "_PUT", "_PATCH", "_DELETE"):
    if k in v:
        conf = v[k]
        print(f"Converting {k} dictionary")
        break

for uri, c in conf.items():
    print(
        f"""
@decorators.endpoint(
    path="{uri}",""",
        end="",
    )
    if "summary" in c:
        print(
            f"""
    summary="{c['summary']}",""",
            end="",
        )

    if "description" in c:
        print(
            f"""
    description="{c['description']}",""",
            end="",
        )

    if "responses" in c:
        print(
            """
    responses={""",
            end="",
        )
        for code, resp in c["responses"].items():
            print(
                f"""
        {code}: "{resp['description']}",""",
                end="",
            )
        print(
            """
    },"""
        )

    print(")", end="")
print("")

for uri, c in conf.items():
    if "responses" in c:
        for code, resp in c["responses"].items():
            resp.pop("description", None)
            if resp:
                log.warning("Unknown key in response with code {}: {}", code, resp)
    c.pop("responses", None)
    c.pop("summary", None)
    c.pop("description", None)
    if c:
        log.warning("Unknown key in {} spec: {}", uri, c)
