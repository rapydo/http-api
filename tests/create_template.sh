#!/bin/bash
set -e

TEMPLATE=$1
AUTH=$2
PROJECT_NAME="prj"

if [[ "$TEMPLATE" == "postgres" ]]; then
  rapydo create ${PROJECT_NAME} --auth postgres --frontend no -e AUTH_TOKEN_IP_GRACE_PERIOD=2
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
  # The flag is not included in all templates to be able to also test the cases
  # when input and output models are not extended

  rapydo --testing create ${PROJECT_NAME} --current \
                    --add-optionals \
                    --extend prjbase \
                    --auth ${AUTH} \
                    --frontend no \
                    -s ftp \
                    -e AUTH_FORCE_FIRST_PASSWORD_CHANGE=1 \
                    -e AUTH_MAX_PASSWORD_VALIDITY=60 \
                    -e AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=60 \
                    -e AUTH_MAX_LOGIN_ATTEMPTS=10 \
                    -e AUTH_SECOND_FACTOR_AUTHENTICATION=1 \
                    -e AUTH_TOKEN_IP_GRACE_PERIOD=2

elif [[ "$TEMPLATE" == "legacy39" ]]; then
  rapydo create ${PROJECT_NAME} --add-optionals \
                    --auth ${AUTH} \
                    --frontend no \
                    -e AUTH_FORCE_FIRST_PASSWORD_CHANGE=1 \
                    -e AUTH_MAX_PASSWORD_VALIDITY=60 \
                    -e AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=60 \
                    -e AUTH_MAX_LOGIN_ATTEMPTS=10 \
                    -e AUTH_SECOND_FACTOR_AUTHENTICATION=1 \
                    -e AUTH_TOKEN_IP_GRACE_PERIOD=2 \
                    -e BACKEND_PYTHON_VERSION="v3.9"

elif [[ "$TEMPLATE" == "legacy310" ]]; then
  rapydo create ${PROJECT_NAME} --add-optionals \
                    --auth ${AUTH} \
                    --frontend no \
                    -e AUTH_FORCE_FIRST_PASSWORD_CHANGE=1 \
                    -e AUTH_MAX_PASSWORD_VALIDITY=60 \
                    -e AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=60 \
                    -e AUTH_MAX_LOGIN_ATTEMPTS=10 \
                    -e AUTH_SECOND_FACTOR_AUTHENTICATION=1 \
                    -e AUTH_TOKEN_IP_GRACE_PERIOD=2 \
                    -e BACKEND_PYTHON_VERSION="v3.10"
elif [[ "$TEMPLATE" == "legacy311" ]]; then
  rapydo create ${PROJECT_NAME} --add-optionals \
                    --auth ${AUTH} \
                    --frontend no \
                    -e AUTH_FORCE_FIRST_PASSWORD_CHANGE=1 \
                    -e AUTH_MAX_PASSWORD_VALIDITY=60 \
                    -e AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=60 \
                    -e AUTH_MAX_LOGIN_ATTEMPTS=10 \
                    -e AUTH_SECOND_FACTOR_AUTHENTICATION=1 \
                    -e AUTH_TOKEN_IP_GRACE_PERIOD=2 \
                    -e BACKEND_PYTHON_VERSION="v3.11"
else
  echo "Unknown template: ${TEMPLATE}";
  exit 1;
fi

git remote add origin https://your_remote_git/your_project.git

# REF contains the branch when commit, but contains refs/pull/XXX/merge on PRs
# with PRs use HEAD_REF

# Strip out refs/heads/ prefix
if [[ ! -z $HEAD_REF_BRANCH ]];
then
  BRANCH=${HEAD_REF_BRANCH/refs\/heads\//}
else
  BRANCH=${REF_BRANCH/refs\/heads\//}
fi

# Also strip out tags from the branch
BRANCH=${BRANCH/refs\/tags\/v/}

echo "Forcing http-api to branch ${BRANCH}"
echo """
  submodules:
    http-api:
      branch: \"${BRANCH}\"
""" >> projects/${PROJECT_NAME}/project_configuration.yaml
