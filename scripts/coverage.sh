
# install requirements in listed order
./dev-requirements.py

mkdir covs

aws configure set aws_access_key_id $S3_USER 
aws configure set aws_secret_access_key $S3_PWD

aws --endpoint-url $S3_HOST s3 sync s3://http-api-${TRAVIS_BUILD_ID} covs

cd covs
ls .coverage*

coverage combine
rapydo --services backend --project template build
docker run -it -v $(pwd):/repo -w /repo template/backend:template coveralls

