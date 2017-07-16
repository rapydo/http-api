#!/bin/bash
set -e

echo "Config is:"
echo "branch=$RAPYDO_BRANCH"
echo "version=$RAPYDO_VERSION"

pip3 install --upgrade rapydo-utils==$RAPYDO_VERSION
pip3 install --upgrade \
    git+https://github.com/rapydo/http-api.git@$RAPYDO_BRANCH
