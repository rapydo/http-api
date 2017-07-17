#!/bin/bash
set -e

rapydodir="core"

export CURRENT_BRANCH=$(git symbolic-ref --short HEAD)
echo "Current branch: $CURRENT_BRANCH"

export CURRENT_VERSION=$(grep __version__ restapi/__init__.py | sed 's/__version__ = //' | tr -d "'")
echo "Current version: $CURRENT_VERSION"

if [ -z $CORE_PROJECT ]; then
    echo "Missing the current testing project with the rapydo core"
    exit 1
fi

if [ ! -d "$rapydodir" ]; then
    git clone https://github.com/rapydo/$rapydodir.git
fi
cd $rapydodir && mkdir -p data
if [ "$CURRENT_BRANCH" != "master" ]; then
    echo "checkout"
    git checkout $CURRENT_BRANCH
fi

cd -
