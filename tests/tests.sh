#!/bin/bash
set -e

if [ ! -d "tests" ]; then
    echo "Missing 'tests' directory"
    exit 1
fi

export COVERAGE_FILE="/tmp/.coverage"

if [[ -z "$1" ]]; then
    CURRENT_PACKAGE="restapi"
else
    CURRENT_PACKAGE=$1
fi

# if [ -z "$2" ]; then
#     folder=tests
# else
#     folder=tests/$2
# fi

if [[ "${CURRENT_PACKAGE}" == "restapi" ]]; then
    coverage_folder="tests/base"
else
    coverage_folder="tests/custom"
fi
echo "Launching unittests with coverage on tests/${2}"
echo "Package: $CURRENT_PACKAGE"
sleep 1

# --timeout is provided by pytest-timeout
# --cov is provided by pytest-cov
if [[ -z "$2" ]]; then
    test_folder="tests/custom tests/base"
else
    test_folder="tests/${2}"
fi

py.test --confcutdir=tests --timeout=300 --durations=5 -x -s --cov-report=xml --cov=${CURRENT_PACKAGE} --cov=${coverage_folder} ${test_folder}
