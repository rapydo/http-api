#!/bin/bash
set -e

rapydodir="tests"

# export CURRENT_BRANCH=$(git symbolic-ref --short HEAD)
# export CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
#https://docs.travis-ci.com/user/environment-variables/#Default-Environment-Variables
echo "Current branch: $TRAVIS_BRANCH"

export CURRENT_VERSION=$(grep __version__ restapi/__init__.py | sed 's/__version__ = //' | tr -d "'")
echo "Current version: $CURRENT_VERSION"

if [ -z $CORE_PROJECT ]; then
    echo "Project ${CORE_PROJECT} not found on rapydo tests"
    exit 1
fi

if [ ! -d "$rapydodir" ]; then
    git clone https://github.com/rapydo/$rapydodir.git
fi
cd $rapydodir && mkdir -p data

chmod -R o+Xw projects
echo "checking permissions:"
ls -ld projects/$CORE_PROJECT/

if [ "$TRAVIS_BRANCH" != "master" ]; then
    echo "checkout $TRAVIS_BRANCH"
    git checkout $TRAVIS_BRANCH
fi

cd -
