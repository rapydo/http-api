#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Implementing a solution to install pip requirements
following the order indicated in the file

# DEPRECATED: not working with pip10
"""

import pip
from restapi import \
    FRAMEWORK_PREFIX, \
    __version__ as current_version

with open('dev-requirements.txt') as requirements:

    for line in requirements:

        if line.startswith('#'):
            continue

        tool_name = line.strip()
        if tool_name == '':
            continue

        if FRAMEWORK_PREFIX in tool_name:
            tool_name += '==' + current_version

        pip.main(
            ['install', '--trusted-host', 'pypi.python.org', '-U', tool_name]
        )
