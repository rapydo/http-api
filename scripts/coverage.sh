#!/bin/bash
set -e

rapydodir="core"

# install requirements in listed order
./dev-requirements.py

echo "Current branch: $TRAVIS_BRANCH"

export CURRENT_VERSION=$(grep __version__ restapi/__init__.py | sed 's/__version__ = //' | tr -d "'")
echo "Current version: $CURRENT_VERSION"

if [ ! -d "$rapydodir" ]; then
    git clone https://github.com/rapydo/$rapydodir.git
fi
cd $rapydodir && mkdir -p data

if [ "$TRAVIS_BRANCH" != "master" ]; then
    echo "checkout $TRAVIS_BRANCH"
    git checkout $TRAVIS_BRANCH
fi

# UP TO HERE THE SCRIPT IS MORE OR LESS A COPY OF test_project.sh

mkdir covs

aws configure set aws_access_key_id $S3_USER 
aws configure set aws_secret_access_key $S3_PWD

aws --endpoint-url $S3_HOST s3 sync s3://http-api-${TRAVIS_BUILD_ID} covs

cd covs
ls .coverage*

coverage combine

rapydo --services backend --project template build
docker run -it -v $(pwd):/repo -w /repo template/backend:template coveralls

