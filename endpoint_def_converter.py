from restapi.utilities.logs import log

_GET = {}

v = vars()
for k in ("_GET", "_POST", "_PUT", "_PATCH", "_DELETE", "_HEAD"):
    if k not in v:
        continue
    conf = v[k]
    print(f"\nConverting {k} dictionary")

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
        summary="{c['summary'].capitalize()}",""",
                end="",
            )

        if "description" in c:
            print(
                f"""
        description="{c['description'].capitalize()}",""",
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
            {code}: "{resp['description'].capitalize()}",""",
                    end="",
                )
            print(
                """
        },""",
                end="",
            )

        print(
            """
    )""",
            end="",
        )
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
