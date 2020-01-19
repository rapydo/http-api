# -*- coding: utf-8 -*-

# TODO: move into base dir

""" Models for elastic search """

from elasticsearch_dsl import DocType, String, Completion

# Date, Nested, Boolean, \
# analyzer, InnerObjectWrapper,


class User(DocType):
    title = String()
    title_suggest = Completion(payloads=True)

    class Meta:
        index = 'someuser'
