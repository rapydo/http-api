#!/bin/bash
set -e

WORK_DIR=`pwd`

# PROJECT=$1

if [ -z $PROJECT ]; then
    echo "Missing the current testing project."
    echo "Use the magic variable COVERAGE for the final step"
    exit 1
fi


# install requirements in listed order
./dev-requirements.py

export CURRENT_VERSION=$(grep __version__ restapi/__init__.py | sed 's/__version__ = //' | tr -d "'")

#https://docs.travis-ci.com/user/environment-variables/#Default-Environment-Variables
if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then 
	echo "Pull request from BRANCH ${TRAVIS_PULL_REQUEST_BRANCH} to ${TRAVIS_BRANCH}"
else
	echo "Current branch: $TRAVIS_BRANCH"
fi
echo "Current project: $PROJECT"
echo "Current version: $CURRENT_VERSION"

CORE_DIR="${WORK_DIR}/core"
COV_DIR="${WORK_DIR}/coverage_files"

echo "WORK_DIR = ${WORK_DIR}"
echo "CORE_DIR = ${CORE_DIR}"
echo "COVERAGE_DIR = ${COV_DIR}"

# Save credentials for S3 storage
aws configure set aws_access_key_id $S3_USER 
aws configure set aws_secret_access_key $S3_PWD

mkdir -p $COV_DIR

if [ ! -d $CORE_DIR ]; then
    git clone https://github.com/rapydo/core.git $CORE_DIR
fi
cd $CORE_DIR
mkdir -p data

# Pull requests
if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then 
	if [ "$TRAVIS_PULL_REQUEST_BRANCH" != "master" ]; then
	    echo "checkout $TRAVIS_PULL_REQUEST_BRANCH"
	    git checkout $TRAVIS_PULL_REQUEST_BRANCH

	    echo "pulling $TRAVIS_BRANCH"
	    git pull origin $TRAVIS_BRANCH
	fi
# Normal commits
else

	if [ "$TRAVIS_BRANCH" != "master" ]; then
	    echo "checkout $TRAVIS_BRANCH"
	    git checkout $TRAVIS_BRANCH
	fi
fi

if [ "$PROJECT" != "COVERAGE" ]; then

	# CURRENT DIR IS $WORK_DIR/core

	# Let's init and start the stack for the configured PROJECT
	rapydo --development --project ${PROJECT} init --skip-bower 
	rapydo --development --project ${PROJECT} start
	docker ps -a
	sleep 40
	docker ps -a
	if [ "$PROJECT" = "celerytest" ]; then
		echo "\n\nLogs from Celery:\n\n"
		docker logs ${PROJECT}_celery_1
	fi
	if [ "$PROJECT" = "irodstest" ]; then
		echo "\n\nLogs from ICAT:\n\n"
		docker logs ${PROJECT}_icat_1
	fi
	echo "\n\nLogs from Backend:\n\n"
	docker logs ${PROJECT}_backend_1

	# Beware!! Cleaning DB before starting the tests
	rapydo --development --project ${PROJECT} shell backend --command 'restapi test_clean_do_not_use_me'
	
	# Test API and calculate coverage
	rapydo --development --project ${PROJECT} shell backend --command 'restapi tests --core'

	if [ "$PROJECT" = "celerytest" ]; then
		echo "\n\nLogs from Celery:\n\n"
		docker logs ${PROJECT}_celery_1
	fi

	# Sync the coverage file to S3, to be available for the next stage
	docker cp ${PROJECT}_backend_1:/code/.coverage $COV_DIR/.coverage.${PROJECT}

	aws --endpoint-url $S3_HOST s3api create-bucket --bucket http-api-${TRAVIS_BUILD_ID}
	aws --endpoint-url $S3_HOST s3 sync $COV_DIR s3://http-api-${TRAVIS_BUILD_ID}

else

	# CURRENT DIR IS $WORK_DIR/core

	PROJECT="template"

	# Download sub-repos (build templates are required)
	rapydo --development --project ${PROJECT} init --skip-bower 
	rapydo --development --project ${PROJECT} --services backend start
	docker ps -a
	# Build the backend image and execute coveralls
	# rapydo --services backend --project ${PROJECT} build

	cd $WORK_DIR

	# Sync coverage files from previous stages
	aws --endpoint-url $S3_HOST s3 sync s3://http-api-${TRAVIS_BUILD_ID} $COV_DIR

    # Combine all coverage files to compute thefinal coverage
	cd $COV_DIR
	ls .coverage*
	coverage combine
	cp $COV_DIR/.coverage $WORK_DIR/

	cd $WORK_DIR
	# docker run -it -v $(pwd):/repo -w /repo template/backend:template coveralls
	docker run -it -v $(pwd):/repo -w /repo rapydo/backend:$CURRENT_VERSION coveralls

fi

cd $CORE_DIR
rapydo --development --project template clean