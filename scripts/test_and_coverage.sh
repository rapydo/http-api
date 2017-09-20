#!/bin/bash
set -e

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
echo "Current branch: $TRAVIS_BRANCH"
echo "Current project: $PROJECT"
echo "Current version: $CURRENT_VERSION"

if [ ! -d "core" ]; then
    git clone https://github.com/rapydo/core.git
fi

cd core
mkdir -p data
mkdir -p coverage_files

if [ "$TRAVIS_BRANCH" != "master" ]; then
    echo "checkout $TRAVIS_BRANCH"
    git checkout $TRAVIS_BRANCH
fi

# Save credentials for S3 storage
aws configure set aws_access_key_id $S3_USER 
aws configure set aws_secret_access_key $S3_PWD

if [ "$PROJECT" != "COVERAGE" ]; then

	# Let's init and start the stack for the configured PROJECT
	rapydo --project ${PROJECT} init --skip-bower 

	rapydo --project ${PROJECT} start
	docker ps -a

	# Test API and calculate coverage
	rapydo --project ${PROJECT} shell backend --command 'restapi tests --wait --core'

	# Sync the coverage file to S3, to be available for the next stage
	docker cp ${PROJECT}_backend_1:/code/.coverage coverage_files/.coverage.${PROJECT}

	aws --endpoint-url $S3_HOST s3api create-bucket --bucket http-api-${TRAVIS_BUILD_ID}
	aws --endpoint-url $S3_HOST s3 sync coverage_files s3://http-api-${TRAVIS_BUILD_ID}

else

	PROJECT="template"

	# Download sub-repos (build templates are required)
	rapydo --project ${PROJECT} init --skip-bower 

	# Sync coverage files from previous stages
	aws --endpoint-url $S3_HOST s3 sync s3://http-api-${TRAVIS_BUILD_ID} coverage_files

    # Combine all coverage files to compute thefinal coverage
	cd coverage_files
	ls .coverage*
	coverage combine
	ls .coverage*
	cd -

	# Build the backend image and execute coveralls
	rapydo --services backend --project ${PROJECT} build

	pwd
	ls
	cat .coveralls.yml
	docker run -it -v $(pwd):/repo -w /repo template/backend:template coveralls


fi

rapydo --project template clean