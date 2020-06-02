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
	py.test --confcutdir=tests -x -s --cov-report=xml $COV tests
else
	py.test --confcutdir=tests -x -s --cov-report=xml $COV tests/$2
fi
