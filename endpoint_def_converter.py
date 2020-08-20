_PUT = {
    "/tests/upload": {
        "summary": "Execute tests with the uploader",
        "description": "Only enabled in testing mode",
        "responses": {"200": {"description": "Tests executed"}},
    },
    "/tests/upload/<chunked>": {
        "summary": "Execute tests with the chunked uploader",
        "description": "Only enabled in testing mode",
        "responses": {"200": {"description": "Tests executed"}},
    },
}

v = vars()
if "_GET" in v:
    conf = v["_GET"]
elif "_POST" in v:
    conf = v["_POST"]
elif "_PUT" in v:
    conf = v["_PUT"]
elif "_PATCH" in v:
    conf = v["_PATCH"]
elif "_DELETE" in v:
    conf = v["_DELETE"]

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
    responses={{""",
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
    }},"""
        )

    print(")")
