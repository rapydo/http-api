#!/bin/bash
set -e

WORK_DIR=$(pwd)

if [ -z $PROJECT ]; then
    echo "Missing the current testing project."
    echo "Use the magic variable COVERAGE for the final step"
    exit 1
fi

# install requirements in listed order
# for package in `cat dev-requirements.txt`;
# do
#     echo "adding: $package";
#     pip3 install --upgrade --no-cache-dir $package;
# done

export CURRENT_VERSION=$(grep __version__ restapi/__init__.py | sed 's/__version__ = //' | tr -d "'")

pip3 install --upgrade --no-cache-dir git+https://github.com/rapydo/do.git@${CURRENT_VERSION}

#https://docs.travis-ci.com/user/environment-variables/#Default-Environment-Variables
if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
	echo "Pull request from BRANCH ${TRAVIS_PULL_REQUEST_BRANCH} to ${TRAVIS_BRANCH}"
else
	echo "Current branch: $TRAVIS_BRANCH"
fi
echo "Current project: $PROJECT"
echo "Current version: $CURRENT_VERSION"

CORE_DIR="${WORK_DIR}/rapydo_tests"

echo "WORK_DIR = ${WORK_DIR}"
echo "CORE_DIR = ${CORE_DIR}"

BRANCH=$([  -z "$TRAVIS_PULL_REQUEST_BRANCH" ] && echo "$TRAVIS_BRANCH" || echo "$TRAVIS_PULL_REQUEST_BRANCH")

git clone -b ${BRANCH} --depth=1 https://github.com/rapydo/tests.git $CORE_DIR

cd $CORE_DIR

# Pull requests
if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then

    echo "pulling $TRAVIS_BRANCH"
    git pull origin $TRAVIS_BRANCH
fi

# CURRENT DIR IS $CORE_DIR

# Let's init and start the stack for the configured PROJECT
rapydo --project ${PROJECT} init

if [[ $TRAVIS_PULL_REQUEST == "false" ]] || [[ $TRAVIS_EVENT_TYPE != "cron" ]]; then
	rapydo pull
fi

rapydo start

sleep 2

rapydo -s backend logs

# Test API and calculate coverage
rapydo shell backend --command 'restapi tests --core --wait'

printf "\n\n\n"

rapydo dump

printf "\n\n\n"

backend_container=$(docker-compose ps -q backend)
docker cp ${backend_container}:/code/coverage.xml coverage.xml

bash <(curl -s https://codecov.io/bash) -R submodules/http-api

printf "\n\n\n"

rapydo remove --all

printf "\n\n\n"

rapydo --production --project ${PROJECT} init --force

rapydo pull
rapydo start
rapydo ssl

printf "\n\n\nBackend server is starting\n\n\n"

sleep 30
rapydo -s backend logs

printf "\n\n\n"

curl -k -X GET --max-time 5 https://localhost/api/status | grep "Server is alive"

printf "\n\n\n"

rapydo remove --all
