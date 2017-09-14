#!/bin/bash
set -e

rapydodir="core"
PROJECT=$1

# install requirements in listed order
./dev-requirements.py

#https://docs.travis-ci.com/user/environment-variables/#Default-Environment-Variables
echo "Current branch: $TRAVIS_BRANCH"

export CURRENT_VERSION=$(grep __version__ restapi/__init__.py | sed 's/__version__ = //' | tr -d "'")
echo "Current version: $CURRENT_VERSION"

if [ -z $PROJECT ]; then
    echo "Missing the current testing project"
    exit 1
fi

if [ ! -d "$rapydodir" ]; then
    git clone https://github.com/rapydo/$rapydodir.git
fi
cd $rapydodir && mkdir -p data

chmod -R o+Xw projects
# echo "checking permissions:"
# ls -ld projects/$CORE_PROJECT/

if [ "$TRAVIS_BRANCH" != "master" ]; then
    echo "checkout $TRAVIS_BRANCH"
    git checkout $TRAVIS_BRANCH
fi

rapydo --project ${PROJECT} init --skip-bower 
rapydo --project ${PROJECT} start
docker ps -a
# sleep 30
# docker logs ${PROJECT}_backend_1
rapydo --project ${PROJECT} shell backend --command 'restapi tests --wait --core'
docker cp ${PROJECT}_backend_1:/code/.coverage ../.coverage.${PROJECT}
rapydo --project ${PROJECT} clean
cd -
