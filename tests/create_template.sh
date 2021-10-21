#!/bin/bash
set -e

TEMPLATE=$1
AUTH=$2

COMMON_OPTIONS=" --frontend no -e AUTH_LOGIN_BAN_TIME=10"

if [[ "$TEMPLATE" == "postgres" ]]; then
  rapydo create prj --auth postgres ${COMMON_OPTIONS} -e AUTH_TOKEN_IP_GRACE_PERIOD=2
elif [[ "$TEMPLATE" == "mysql" ]]; then
  rapydo create prj --auth mysql ${COMMON_OPTIONS} -e AUTH_TOKEN_IP_GRACE_PERIOD=2
elif [[ "$TEMPLATE" == "neo4j" ]]; then
  rapydo create prj --auth neo4j ${COMMON_OPTIONS} -e AUTH_TOKEN_IP_GRACE_PERIOD=2
elif [[ "$TEMPLATE" == "mongo" ]]; then
  rapydo create prj --auth mongo ${COMMON_OPTIONS} -e AUTH_TOKEN_IP_GRACE_PERIOD=2
elif [[ "$TEMPLATE" == "celery-rabbit-rabbit" ]]; then
  rapydo create prj -s celery -s rabbit --auth ${AUTH} ${COMMON_OPTIONS};
elif [[ "$TEMPLATE" == "celery-rabbit-redis" ]]; then
  rapydo create prj -s celery -s rabbit -s redis --auth ${AUTH} ${COMMON_OPTIONS};
elif [[ "$TEMPLATE" == "celery-rabbit-mongo" ]]; then
  rapydo create prj -s celery -s rabbit -s mongo --auth ${AUTH} ${COMMON_OPTIONS};
elif [[ "$TEMPLATE" == "celery-redis-redis" ]]; then
  rapydo create prj -s celery -s redis --auth ${AUTH} ${COMMON_OPTIONS};
elif [[ "$TEMPLATE" == "celery-redis-mongo" ]]; then
  rapydo create prj -s celery -s redis -s mongo --auth ${AUTH} ${COMMON_OPTIONS};
elif [[ "$TEMPLATE" == "noauth" ]]; then
  rapydo create prj --auth no ${COMMON_OPTIONS}

elif [[ "$TEMPLATE" == "extra" ]]; then
  rapydo create prjbase --auth ${AUTH} ${COMMON_OPTIONS} -e PROXIED_CONNECTION=1
  # the --testing flag here (not included in others templates) will extend the
  # customizer class with additinal input/output fields to test these customizations
  # The flag is not included in all templates to be able to also tests the cases
  # when input and output models are not extended

  rapydo --testing create prj --current \
                    --add-optionals \
                    --extend prjbase \
                    --auth ${AUTH} \
                    ${COMMON_OPTIONS} \
                    -s ftp \
                    -s pushpin \
                    -s bot \
                    -e AUTH_FORCE_FIRST_PASSWORD_CHANGE=1 \
                    -e AUTH_MAX_PASSWORD_VALIDITY=60 \
                    -e AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=60 \
                    -e AUTH_MAX_LOGIN_ATTEMPTS=10 \
                    -e AUTH_SECOND_FACTOR_AUTHENTICATION=1 \
                    -e AUTH_TOKEN_IP_GRACE_PERIOD=2

else
  echo "Unknown template: ${TEMPLATE}";
  exit 1;
fi

git remote add origin https://your_remote_git/your_project.git