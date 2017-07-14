#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Implementing a solution to install pip requirements
following the order indicated in the file
"""

import pip
from restapi import \
    FRAMEWORK_PREFIX, \
    __version__ as current_version

with open('dev-requirements.txt') as requirements:

    for line in requirements:

        if line.startswith('#'):
            continue
        else:
            tool_name = line.strip()

        if FRAMEWORK_PREFIX in tool_name:
            tool_name += '==' + current_version

        pip.main(['install', '-U', tool_name])
