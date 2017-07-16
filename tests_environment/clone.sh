#!/bin/bash
set -e

# check for CORE_PROJECT and CURRENT_BRANCH

YAMLFILE="projects/$CORE_PROJECT/confs/commons.yml"

# TODO: use a branch for 'http' core' ?
git clone https://github.com/rapydo/core.git
# - if CURRENT_BRANCH != master git checkout $CURRENT_BRANCH
cd core && mkdir data

# TODO: use environment variable from outside to set the branch?

# fix the backend build with the latest http-api to be tested
mkdir -p builds/backend && cp ../core/Dockerfile builds/backend/
# add a docker-entrypoint.d/script to update with pip
tail -n +7  $YAMLFILE > ../core/tail.yml
cat../core/head.yml ../core/tail.yml $YAMLFILE
