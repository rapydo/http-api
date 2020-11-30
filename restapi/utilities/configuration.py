import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, cast

import yaml

from restapi.utilities import print_and_exit
from restapi.utilities.logs import log

PROJECTS_DEFAULTS_FILE = Path("projects_defaults.yaml")
PROJECT_CONF_FILENAME = Path("project_configuration.yaml")


ConfigurationType = Dict[str, Any]


def read_configuration(
    default_file_path: Path,
    base_project_path: Path,
    projects_path: Path,
    submodules_path: Path,
) -> Tuple[ConfigurationType, Optional[str], Optional[Path]]:
    """
    Read default configuration
    """

    custom_configuration = load_yaml_file(PROJECT_CONF_FILENAME, path=base_project_path)

    # Verify custom project configuration
    project = custom_configuration.get("project")
    # Can't be tested because it is included in default configuration
    if project is None:  # pragma: no cover
        raise AttributeError("Missing project configuration")

    variables = ["title", "description", "version", "rapydo"]

    for key in variables:
        # Can't be tested because it is included in default configuration
        if project.get(key) is None:  # pragma: no cover
            print_and_exit(
                "Project not configured, missing key '{}' in file {}/{}",
                key,
                base_project_path,
                PROJECT_CONF_FILENAME,
            )

    base_configuration = load_yaml_file(
        file=PROJECTS_DEFAULTS_FILE, path=default_file_path
    )

    extended_project = project.get("extends")

    if extended_project is None:
        # Mix default and custom configuration
        return mix(base_configuration, custom_configuration), None, None

    extends_from = project.get("extends-from", "projects")

    if extends_from == "projects":
        extend_path = projects_path
    elif extends_from.startswith("submodules/"):  # pragma: no cover
        repository_name = (extends_from.split("/")[1]).strip()
        if repository_name == "":
            print_and_exit("Invalid repository name in extends-from, name is empty")

        extend_path = submodules_path
    else:  # pragma: no cover
        suggest = "Expected values: 'projects' or 'submodules/${REPOSITORY_NAME}'"
        print_and_exit("Invalid extends-from parameter: {}.\n{}", extends_from, suggest)

    if not os.path.exists(extend_path):  # pragma: no cover
        print_and_exit("From project not found: {}", extend_path)

    extend_file = Path(f"extended_{PROJECT_CONF_FILENAME}")
    extended_configuration = load_yaml_file(file=extend_file, path=extend_path)
    m1 = mix(base_configuration, extended_configuration)
    return mix(m1, custom_configuration), extended_project, extend_path


def mix(base: ConfigurationType, custom: ConfigurationType) -> ConfigurationType:

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


def load_yaml_file(file: Path, path: Path) -> ConfigurationType:

    filepath = os.path.join(path, file)

    if not os.path.exists(filepath):
        raise AttributeError(f"YAML file does not exist: {filepath}")

    with open(filepath) as fh:
        try:
            docs = list(yaml.load_all(fh, yaml.loader.Loader))

            if len(docs) == 0:
                raise AttributeError(f"YAML file is empty: {filepath}")

            return cast(ConfigurationType, docs[0])

        except Exception as e:
            # # IF dealing with a strange exception string (escaped)
            # import codecs
            # error, _ = codecs.getdecoder("unicode_escape")(str(error))

            raise AttributeError(f"Failed to read file {filepath}: {e}")
