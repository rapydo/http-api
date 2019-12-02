# -*- coding: utf-8 -*-

import sys
import os
import yaml
import json

from restapi.utilities.configuration import mix
from restapi.utilities.logs import log

if len(sys.argv) <= 1:
    log.exit("Usage: {} project_name", sys.argv[0])

PROJECT = sys.argv[1]
PROJECT_DIR = "projects/{}/backend/swagger".format(PROJECT)

if not os.path.exists(PROJECT_DIR):
    log.exit("{} folder does not exist", PROJECT_DIR)

if not os.path.isdir(PROJECT_DIR):
    log.exit("{} is not a folder", PROJECT_DIR)

yamls = ["specs", "get", "post", "put", "patch", "delete", "head"]
for swagger_folder in os.listdir(PROJECT_DIR):

    conf_output = ""
    decorators_output = ""
    pfile = None
    pclass = None
    mappings = None
    for y in yamls:
        f = os.path.join(PROJECT_DIR, swagger_folder, y + ".yaml")

        if not os.path.isfile(f):
            continue

        with open(f, 'r') as yaml_in:
            yaml_object = yaml.safe_load(yaml_in)
            j = json.loads(json.dumps(yaml_object))

            if y == 'specs':
                pfile = j.pop('file')
                pclass = j.pop('class')
                schema = j.pop('schema', None)
                baseuri = j.pop('baseuri', None)
                if schema is not None:
                    schema = schema.get('expose', False)
                labels = j.pop('labels', [])
                depends_on = j.pop('depends_on', [])
                mappings = j.pop("mapping")

                if len(j) > 0:
                    log.exit("Found unexpected key: {}", j)

                if baseuri is not None:
                    conf_output += "\nbaseuri = '{}'".format(baseuri)

                if schema:
                    conf_output += "\n# schema_expose = True"

                conf_output += "\nlabels = {}".format(labels)

                if len(depends_on) > 0:
                    conf_output += "\ndepends_on = {}".format(depends_on)
            else:
                common = j.pop('common', {})
                # log.critical(common)
                keys = set(j.keys())
                data = {}
                for m in keys:
                    if m not in mappings:
                        log.exit("Missing {} label in {}.{}.specs", m, pfile, pclass)

                    u = mappings.get(m)

                    conf = mix(common, j.pop(m))

                    if 'custom' in conf:
                        auth = conf['custom'].pop('authentication', False)
                        roles = conf['custom'].pop('authorized', None)
                        req_roles = conf['custom'].pop('required_roles', None)

                        if auth:
                            decorators_output += "\n@authentication.required("
                            if roles is not None:
                                decorators_output += "roles={}".format(roles)
                            if req_roles is not None:
                                if roles is not None:
                                    decorators_output += ", "
                                decorators_output += "required_roles='{}'".format(
                                    req_roles)
                            decorators_output += ")"

                            decorators_output += "\ndef {}(self...\n".format(y)
                    data[u] = conf

                if len(j) > 0:
                    log.exit("Found unexpected key: {}", j)
                conf_output += "\n{} = {}".format(y.upper(), data)

    print("***************************************")
    print("# Conf in {}.{} ({})".format(pfile, pclass, swagger_folder))
    print(conf_output)
    if len(decorators_output) > 0:
        print("\nfrom restapi.protocols.bearer import authentication")
    print(decorators_output)
