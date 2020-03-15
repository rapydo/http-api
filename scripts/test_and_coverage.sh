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

if [ ! -d $CORE_DIR ]; then
    git clone https://github.com/rapydo/tests.git $CORE_DIR
fi
cd $CORE_DIR
mkdir -p data

# Pull requests
if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
    echo "checkout $TRAVIS_PULL_REQUEST_BRANCH"
    git checkout $TRAVIS_PULL_REQUEST_BRANCH

    echo "pulling $TRAVIS_BRANCH"
    git pull origin $TRAVIS_BRANCH
# Normal commits
else

    echo "checkout $TRAVIS_BRANCH"
    git checkout $TRAVIS_BRANCH
fi

# CURRENT DIR IS $CORE_DIR

echo "project: ${PROJECT}" > .projectrc
echo "project_configuration:" >> .projectrc
echo "  variables:" >> .projectrc
echo "    env:" >> .projectrc
echo "      DEFAULT_DHLEN: 256" >> .projectrc
echo "      NEO4J_AUTOINDEXING: False" >> .projectrc
echo "      NEO4J_PASSWORD: AutoT3sts" >> .projectrc
echo "      RABBITMQ_USER: white" >> .projectrc
echo "      RABBITMQ_PASSWORD: rabbit" >> .projectrc
echo "      AUTH_DEFAULT_USERNAME: test@nomail.org" >> .projectrc
echo "      AUTH_DEFAULT_PASSWORD: testme" >> .projectrc

# Let's init and start the stack for the configured PROJECT
rapydo init

if [[ $TRAVIS_PULL_REQUEST == "false" ]] || [[ $TRAVIS_EVENT_TYPE != "cron" ]]; then
	rapydo pull
fi

rapydo start
docker ps -a

# Test API and calculate coverage
rapydo shell backend --command 'restapi tests --core --wait'

printf "\n\n\n"

rapydo dump

printf "\n\n\n"

backend_container=$(docker-compose ps -q backend)
docker cp ${backend_container}:/code/coverage.xml coverage.xml

bash <(curl -s https://codecov.io/bash) -R submodules/http-api

printf "\n\n\n"

rapydo clean

printf "\n\n\n"

rapydo --production pull
rapydo --production start
rapydo --production ssl-certificate

printf "\n\n\nBackend server is starting\n\n\n"

rapydo --production shell backend --command 'restapi wait'
rapydo --production -s backend logs

printf "\n\n\n"

curl -k -X GET https://localhost/api/status | grep "Server is alive!"

printf "\n\n\n"

rapydo --production remove
rapydo --production clean
