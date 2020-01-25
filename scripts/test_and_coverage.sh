#!/bin/bash
set -e

WORK_DIR=`pwd`

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

pip3 install --upgrade --no-cache-dir awscli==1.15.70 git+https://github.com/rapydo/do.git@${CURRENT_VERSION}
# six==1.11.0
# git+https://github.com/rapydo/http-api.git@0.7.2

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

if [[ "$PROJECT" == "COVERAGE" ]]; then

    pip3 install --upgrade --no-cache-dir coveralls git+https://github.com/rapydo/http-api.git@${CURRENT_VERSION}
	# Sync coverage files from previous stages
	aws --endpoint-url $S3_HOST s3 sync s3://http-api-${TRAVIS_BUILD_ID} $COV_DIR

	# Verify if this path exists:
	ls -d /home/travis/virtualenv/python3.7.1/lib/python3.7/site-packages/restapi/
	# The entries in this section are lists of file paths that should be considered
	# equivalent when combining data from different machines:
	echo '[paths]' > $COV_DIR/.coveragerc
	echo 'source =' >> $COV_DIR/.coveragerc
	# The first value must be an actual file path on the machine where the reporting
	# will happen, so that source code can be found.
	echo '    /home/travis/virtualenv/python3.7.1/lib/python3.7/site-packages/restapi/' >> $COV_DIR/.coveragerc
	# The other values can be file patterns to match against the paths of collected
	# data, or they can be absolute or relative file paths on the current machine.      
	echo '    /usr/local/lib/python3.5/dist-packages/restapi/' >> $COV_DIR/.coveragerc
	echo '    /usr/local/lib/python3.6/dist-packages/restapi/' >> $COV_DIR/.coveragerc
	echo '    /usr/local/lib/python3.7/dist-packages/restapi/' >> $COV_DIR/.coveragerc
	echo '    /usr/local/lib/python3.8/dist-packages/restapi/' >> $COV_DIR/.coveragerc

else

	# CURRENT DIR IS $CORE_DIR

	echo "project: ${PROJECT}" > .projectrc
	echo "project_configuration:" >> .projectrc
	echo "  variables:" >> .projectrc
	echo "    env:" >> .projectrc
	echo "      DEFAULT_DHLEN: 256" >> .projectrc
	echo "      GRAPHDB_AUTOINDEXING: False" >> .projectrc
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

	rapydo shell backend --command 'restapi --help'
	timeout 60s rapydo shell backend --command 'restapi wait' || true
	rapydo --production -s backend logs

	echo "\n\n\n"

	# Cleaning DB before starting the tests
	rapydo shell backend --command 'restapi forced-clean'
	rapydo shell backend --command 'restapi init'

	echo "\n\n\n"

	# Test API and calculate coverage
	rapydo shell backend --command 'restapi tests --core'

	echo "\n\n\n"

	# Sync the coverage file to S3, to be available for the next stage
	rapydo dump

	echo "\n\n\n"

	backend_container=$(docker-compose ps -q backend)
	docker cp ${backend_container}:$COVERAGE_FILE $COV_DIR/.coverage.${PROJECT}

	aws --endpoint-url $S3_HOST s3api create-bucket --bucket http-api-${TRAVIS_BUILD_ID}
	aws --endpoint-url $S3_HOST s3 sync $COV_DIR s3://http-api-${TRAVIS_BUILD_ID}

	echo "\n\n\n"

	rapydo clean

	echo "\n\n\n"

	rapydo --production pull
	rapydo --production start
	rapydo --production ssl-certificate

	echo "\n\nBackend server is starting\n\n"
	timeout 60s rapydo shell backend --command 'restapi wait' || true
	rapydo --production -s backend logs

	echo "\n\n\n"

	curl -k -X GET https://localhost/api/status | grep "Server is alive!"

	echo "\n\n\n"

	rapydo --production remove
	rapydo --production clean

fi
