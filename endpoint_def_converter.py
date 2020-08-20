_GET = {
    "/logout": {
        "summary": "Logout from current credentials",
        "description": "Invalidate current registered token",
        "responses": {"204": {"description": "Token correctly removed"}},
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
