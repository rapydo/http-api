#!/bin/bash
set -e

if [ ! -d "tests" ]; then
    echo "Missing 'tests' directory"
    exit 1
fi

export COVERAGE_FILE="/tmp/.coverage"

if [ -z "$1" -o "$1" = "default" ]; then
    CURRENT_PACKAGE="$VANILLA_PACKAGE"
    COV="--cov=$CURRENT_PACKAGE.apis --cov=$CURRENT_PACKAGE.tasks --cov=$CURRENT_PACKAGE.models"
else
    CURRENT_PACKAGE=$1
    COV="--cov=$CURRENT_PACKAGE"
fi

echo "Launching unittests with coverage"
echo "Package: $CURRENT_PACKAGE"
sleep 1

if [ -z "$2" ]; then
	py.test --confcutdir=tests -x -s --cov-report=xml $COV tests
else
	py.test --confcutdir=tests -x -s --cov-report=xml $COV tests/$2
fi
