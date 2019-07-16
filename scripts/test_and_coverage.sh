#!/bin/bash
set -e

WORK_DIR=`pwd`

# PROJECT=$1

if [ -z $PROJECT ]; then
    echo "Missing the current testing project."
    echo "Use the magic variable COVERAGE for the final step"
    exit 1
fi

# PIP10 DEBUG
# pip install --upgrade pip

# install requirements in listed order
# ./dev-requirements.py
for package in `cat dev-requirements.txt`;
do
    echo "adding: $package";
    pip3 install --upgrade --no-cache-dir $package;
done

export CURRENT_VERSION=$(grep __version__ restapi/__init__.py | sed 's/__version__ = //' | tr -d "'")

#https://docs.travis-ci.com/user/environment-variables/#Default-Environment-Variables
if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
	echo "Pull request from BRANCH ${TRAVIS_PULL_REQUEST_BRANCH} to ${TRAVIS_BRANCH}"
else
	echo "Current branch: $TRAVIS_BRANCH"
fi
echo "Current project: $PROJECT"
echo "Current version: $CURRENT_VERSION"

CORE_DIR="${WORK_DIR}/rapydo_tests"
COV_DIR="${WORK_DIR}/coverage_files"
COVERAGE_FILE="/tmp/.coverage"

echo "WORK_DIR = ${WORK_DIR}"
echo "CORE_DIR = ${CORE_DIR}"
echo "COVERAGE_DIR = ${COV_DIR}"

# Save credentials for S3 storage
# echo "TEST *${S3_USER}* *${S3_PWD}*"
aws configure set aws_access_key_id $S3_USER
aws configure set aws_secret_access_key $S3_PWD

mkdir -p $COV_DIR

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

if [ "$PROJECT" != "COVERAGE" ]; then

	# CURRENT DIR IS $CORE_DIR

	# Let's init and start the stack for the configured PROJECT
	rapydo --development --project ${PROJECT} init

	if [[ $TRAVIS_PULL_REQUEST == "false" ]] || [[ $TRAVIS_EVENT_TYPE != "cron" ]]; then
		rapydo --development --project ${PROJECT} pull
	fi

	rapydo --development --project ${PROJECT} init

	rapydo --development --project ${PROJECT} start
	docker ps -a

	rapydo --development --project ${PROJECT} shell backend --command 'restapi --help'
	# Beware!! Cleaning DB before starting the tests
	rapydo --development --project ${PROJECT} shell backend --command 'restapi wait'
	rapydo --development --project ${PROJECT} shell backend --command 'restapi forced-clean'

	# Test API and calculate coverage
	rapydo --development --project ${PROJECT} shell backend --command 'restapi tests --core'

	# if [ "$PROJECT" = "celerytest" ]; then
	# 	echo "\n\nLogs from Celery:\n\n"
	# 	docker logs ${PROJECT}_celery_1
	# fi

	# Sync the coverage file to S3, to be available for the next stage
	rapydo --development --project ${PROJECT} dump
	backend_container=$(docker-compose ps -q backend)
	docker cp ${backend_container}:$COVERAGE_FILE $COV_DIR/.coverage.${PROJECT}

	aws --endpoint-url $S3_HOST s3api create-bucket --bucket http-api-${TRAVIS_BUILD_ID}
	aws --endpoint-url $S3_HOST s3 sync $COV_DIR s3://http-api-${TRAVIS_BUILD_ID}

	rapydo --development --project ${PROJECT} clean

	echo "project_configuration:" > .projectrc
	echo "  variables:" >> .projectrc
	echo "    env:" >> .projectrc
	echo "      DEFAULT_DHLEN: 256" >> .projectrc

	rapydo --mode production --project ${PROJECT} pull
	rapydo --mode production --project ${PROJECT} start

	sleep 20

	curl -k -X GET https://localhost/api/status | grep "Server is alive!"

	rapydo --mode production --project ${PROJECT} remove
	rapydo --mode production --project ${PROJECT} clean

else

	# cd $WORK_DIR

	# Sync coverage files from previous stages
	aws --endpoint-url $S3_HOST s3 sync s3://http-api-${TRAVIS_BUILD_ID} $COV_DIR

 #    # Combine all coverage files to compute the final coverage
	# cd $COV_DIR
	# ls .coverage*
	# echo "x"
	# echo $COVERALLS_REPO_TOKEN
	# echo "y"
	# echo $TRAVIS
	# echo "z"
	# coverage combine
	# cp $COV_DIR/.coverage $WORK_DIR/

	# cd $WORK_DIR

	# # CURRENT DIR IS $CORE_DIR

	# PROJECT="template"

	# # Download sub-repos (build templates are required)
	# rapydo --development --project ${PROJECT} init
	# if [[ $TRAVIS_PULL_REQUEST == "false" ]] || [[ $TRAVIS_EVENT_TYPE != "cron" ]]; then
	# 	rapydo --development --project ${PROJECT} pull
	# fi
	# # rapydo --development --project ${PROJECT} init
	# rapydo --development --project ${PROJECT} --services backend start
	# docker ps -a


	# # docker run -it -v $(pwd):/repo -e COVERALLS_REPO_TOKEN:$COVERALLS_REPO_TOKEN -w /repo rapydo/backend:$CURRENT_VERSION coveralls

	# coveralls

	# cd $CORE_DIR
	# rapydo --development --project template clean
fi
