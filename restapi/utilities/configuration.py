# -*- coding: utf-8 -*-

import os
from collections import OrderedDict
import yaml
from restapi.utilities.logs import log


PROJECTS_DEFAULTS_FILE = 'projects_defaults.yaml'
PROJECT_CONF_FILENAME = 'project_configuration.yaml'


def read_configuration(
        default_file_path, base_project_path, projects_path, submodules_path):
    """
    Read default configuration
    """

    custom_configuration = load_yaml_file(
        PROJECT_CONF_FILENAME, path=base_project_path, keep_order=True
    )

    # Verify custom project configuration
    project = custom_configuration.get('project')
    if project is None:
        raise AttributeError("Missing project configuration")

    variables = ['title', 'description', 'version', 'rapydo']

    for key in variables:
        if project.get(key) is None:

            log.exit(
                "Project not configured, missing key '{}' in file {}/{}",
                key,
                base_project_path,
                PROJECT_CONF_FILENAME,
            )

    if default_file_path is None:
        base_configuration = {}
    else:
        base_configuration = load_yaml_file(
            file=PROJECTS_DEFAULTS_FILE, path=default_file_path, keep_order=True)

    extended_project = project.get('extends')

    if extended_project is None:
        # Mix default and custom configuration
        return mix(base_configuration, custom_configuration), None, None

    extends_from = project.get('extends-from', 'projects')

    if extends_from == "projects":
        extend_path = projects_path
    elif extends_from.startswith("submodules/"):
        repository_name = (extends_from.split("/")[1]).strip()
        if repository_name == '':
            log.exit('Invalid repository name in extends-from, name is empty')

        extend_path = submodules_path
    else:
        suggest = "Expected values: 'projects' or 'submodules/${REPOSITORY_NAME}'"
        log.exit("Invalid extends-from parameter: {}.\n{}", extends_from, suggest)

    if not os.path.exists(extend_path):
        log.exit("From project not found: {}", extend_path)

    extend_file = "extended_{}".format(PROJECT_CONF_FILENAME)
    extended_configuration = load_yaml_file(
        file=extend_file, path=extend_path, keep_order=True)
    m1 = mix(base_configuration, extended_configuration)
    return mix(m1, custom_configuration), extended_project, extend_path


def mix(base, custom):
    if base is None:
        base = {}

    for key, elements in custom.items():

        if key not in base:
            base[key] = custom[key]
            continue

        if elements is None:
            if isinstance(base[key], dict):
                log.warning("Cannot replace {} with empty list", key)
                continue

        if isinstance(elements, dict):
            mix(base[key], custom[key])

        elif isinstance(elements, list):
            for e in elements:
                base[key].append(e)
        else:
            base[key] = elements

    return base


class OrderedLoader(yaml.SafeLoader):
    """
    A 'workaround' good enough for ordered loading of dictionaries

    https://stackoverflow.com/a/21912744

    NOTE: This was created to skip dependencies.
    Otherwise this option could be considered:
    https://pypi.python.org/pypi/ruamel.yaml
    """

    pass


def construct_mapping(loader, node):
    loader.flatten_mapping(node)
    return OrderedDict(loader.construct_pairs(node))


def load_yaml_file(file, path, keep_order=False):

    filepath = os.path.join(path, file)

    log.verbose("Reading file {}", filepath)

    if not os.path.exists(filepath):
        raise AttributeError("YAML file does not exist: {}".format(filepath))

    with open(filepath) as fh:
        try:
            if keep_order:

                OrderedLoader.add_constructor(
                    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                    construct_mapping
                )
                loader = yaml.load_all(fh, OrderedLoader)
            else:
                loader = yaml.load_all(fh, yaml.loader.Loader)

            docs = list(loader)

            if len(docs) == 0:
                raise AttributeError("YAML file is empty: {}".format(filepath))

            return docs[0]

        except Exception as e:
            # # IF dealing with a strange exception string (escaped)
            # import codecs
            # error, _ = codecs.getdecoder("unicode_escape")(str(error))

            raise AttributeError("Failed to read file {}: {}".format(filepath, e))
