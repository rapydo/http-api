from typing import Any, List, Optional

from flask_apispec.utils import Annotation


def inject_apispec_docs(fn: Any, conf: Any, labels: Optional[List[str]]) -> None:

    # retrieve attributes already set with @docs decorator
    fn.__apispec__ = fn.__dict__.get("__apispec__", {})
    docs = {}
    # it is normally available after loading the endpoint
    # but it is still un-initialized when using the @endpoint decorator
    if "docs" not in fn.__apispec__:
        fn.__apispec__["docs"] = []
    else:
        for doc in fn.__apispec__["docs"]:
            docs.update(doc.options[0])

    missing = {}
    if "summary" not in docs:
        summary = conf.get("summary")
        if summary is not None:
            missing["summary"] = summary

    if "description" not in docs:
        description = conf.get("description")
        if description is not None:
            missing["description"] = description

    if "tags" not in docs:
        if labels:
            missing["tags"] = labels

    if responses := conf.get("responses"):
        if "responses" not in docs:
            missing["responses"] = responses
        else:
            for code, resp in responses.items():
                if code not in docs["responses"]:
                    missing.setdefault("responses", {})
                    missing["responses"][code] = resp

    # mimic the behaviour of @docs decorator
    # https://github.com/jmcarp/flask-apispec/...
    #                         .../flask_apispec/annotations.py
    annotation = Annotation(
        options=[missing],
        # Inherit Swagger documentation from parent classes
        # None is the default value
        inherit=None,
    )
    fn.__apispec__["docs"].insert(0, annotation)
