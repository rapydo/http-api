#!/bin/bash
set -e

TEMPLATE=$1
AUTH=$2
PROJECT_NAME="prj"

if [[ "$TEMPLATE" == "postgres" ]]; then
  rapydo create ${PROJECT_NAME} --auth postgres --frontend no -e AUTH_TOKEN_IP_GRACE_PERIOD=2
elif [[ "$TEMPLATE" == "mysql" ]]; then
  rapydo create ${PROJECT_NAME} --auth mysql --frontend no -e AUTH_TOKEN_IP_GRACE_PERIOD=2
elif [[ "$TEMPLATE" == "neo4j" ]]; then
  rapydo create ${PROJECT_NAME} --auth neo4j --frontend no -e AUTH_TOKEN_IP_GRACE_PERIOD=2
elif [[ "$TEMPLATE" == "celery-rabbit-rabbit" ]]; then
  rapydo create ${PROJECT_NAME} -s celery -s rabbit --auth ${AUTH} --frontend no;
elif [[ "$TEMPLATE" == "celery-rabbit-redis" ]]; then
  rapydo create ${PROJECT_NAME} -s celery -s rabbit -s redis --auth ${AUTH} --frontend no;
elif [[ "$TEMPLATE" == "celery-redis-redis" ]]; then
  rapydo create ${PROJECT_NAME} -s celery -s redis --auth ${AUTH} --frontend no;
elif [[ "$TEMPLATE" == "low_security" ]]; then
  rapydo --testing create ${PROJECT_NAME} --current \
                    --auth ${AUTH} \
                    --frontend no \
                    -e AUTH_FORCE_FIRST_PASSWORD_CHANGE=0 \
                    -e AUTH_MAX_PASSWORD_VALIDITY=0 \
                    -e AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=0 \
                    -e AUTH_MAX_LOGIN_ATTEMPTS=0 \
                    -e AUTH_SECOND_FACTOR_AUTHENTICATION=0 \
                    -e AUTH_TOKEN_IP_GRACE_PERIOD=99999999999
elif [[ "$TEMPLATE" == "noauth" ]]; then
  rapydo create ${PROJECT_NAME} --auth no --frontend no

elif [[ "$TEMPLATE" == "extra" ]]; then
  rapydo create prjbase --auth ${AUTH} --frontend no -e PROXIED_CONNECTION=1
  # the --testing flag here (not included in others templates) will extend the
  # customizer class with additinal input/output fields to test these customizations
  # The flag is not included in all templates to be able to also tests the cases
  # when input and output models are not extended

  rapydo --testing create ${PROJECT_NAME} --current \
                    --add-optionals \
                    --extend prjbasebase \
                    --auth ${AUTH} \
                    --frontend no \
                    -s ftp \
                    -e AUTH_FORCE_FIRST_PASSWORD_CHANGE=1 \
                    -e AUTH_MAX_PASSWORD_VALIDITY=60 \
                    -e AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=60 \
                    -e AUTH_MAX_LOGIN_ATTEMPTS=10 \
                    -e AUTH_SECOND_FACTOR_AUTHENTICATION=1 \
                    -e AUTH_TOKEN_IP_GRACE_PERIOD=2
# no longer needed because it is a default during tests now
                    #-e AUTH_LOGIN_BAN_TIME=10 \
else
  echo "Unknown template: ${TEMPLATE}";
  exit 1;
fi

git remote add origin https://your_remote_git/your_project.git

if [[ ! -z $github.head_ref ]];
  BRANCH=${{ github.head_ref }}
else
  BRANCH=${{ github.ref }}
fi

echo "Forcing http-api to branch ${BRANCH}"
sed -i "s|# branch: http-api-branch|branch: ${BRANCH}|g" projects/${PROJECT_NAME}/project_configuration.yaml
