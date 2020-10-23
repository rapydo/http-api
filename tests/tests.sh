#!/bin/bash
set -e

if [ ! -d "tests" ]; then
    echo "Missing 'tests' directory"
    exit 1
fi

export COVERAGE_FILE="/tmp/.coverage"


CURRENT_PACKAGE="restapi"
COV="--cov=$CURRENT_PACKAGE"

echo "Launching unittests with coverage"
echo "Package: $CURRENT_PACKAGE"
sleep 1

if [ -z "$2" ]; then
    folder=tests
else
    folder=tests/$2
fi

# --timeout is powered by pytest-timeout
py.test --confcutdir=tests --timeout=300 -x -s --cov-report=xml $COV $folder
