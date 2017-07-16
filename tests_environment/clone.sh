#!/bin/bash
set -e

mydir="../tests_environment"
rapydodir="core"

export CURRENT_BRANCH=$(git symbolic-ref --short HEAD)
export CURRENT_VERSION=$(grep __version__ restapi/__init__.py | sed 's/__version__ = //' | tr -d "'")
echo "Current branch: $CURRENT_BRANCH"

if [ -z $CORE_PROJECT ]; then
    echo "Missing the current testing project with the rapydo core"
    return
fi

export YAMLFILE="projects/$CORE_PROJECT/confs/commons.yml"
echo "config: $YAMLFILE"

if [ ! -d "$rapydodir" ]; then
    git clone https://github.com/rapydo/$rapydodir.git
fi
cd $rapydodir && mkdir -p data
if [ "$CURRENT_BRANCH" != "master" ]; then
    echo "checkout"
    git checkout $CURRENT_BRANCH
fi

# fix the backend build with the latest http-api to be tested
mkdir -p builds/backend && cp $mydir/Dockerfile builds/backend/
echo "updated build"

# force the build within the docker compose options
if [ ! -f "$mydir/converted" ]; then
    tail -n +7 $YAMLFILE > $mydir/tail.yml
    touch $mydir/converted
    cat $mydir/head.yml $mydir/tail.yml > $YAMLFILE
    echo "updated commons"
fi

cd -
