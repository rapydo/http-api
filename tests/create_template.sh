#!/bin/bash
set -e

TEMPLATE=$1
AUTH=$2

if [[ "$TEMPLATE" == "postgres" ]]; then
  # TOTP will be checked and disabled because AUTH_FORCE_FIRST_PASSWORD_CHANGE is 0;
  rapydo create prj --auth postgres --frontend no -e AUTH_SECOND_FACTOR_AUTHENTICATION=TOTP;
elif [[ "$TEMPLATE" == "mysql" ]]; then
  # TOTP will be checked and disabled because AUTH_FORCE_FIRST_PASSWORD_CHANGE is 0;
  rapydo create prj --auth mysql --frontend no -e AUTH_SECOND_FACTOR_AUTHENTICATION=TOTP;
elif [[ "$TEMPLATE" == "neo4j" ]]; then
  # TOTP will be checked and disabled because AUTH_FORCE_FIRST_PASSWORD_CHANGE is 0;
  rapydo create prj --auth neo4j --frontend no -e AUTH_SECOND_FACTOR_AUTHENTICATION=TOTP;
elif [[ "$TEMPLATE" == "mongo" ]]; then
  # TOTP will be checked and disabled because AUTH_FORCE_FIRST_PASSWORD_CHANGE is 0;
  rapydo create prj --auth mongo --frontend no -e AUTH_SECOND_FACTOR_AUTHENTICATION=TOTP;


elif [[ "$TEMPLATE" == "celery-rabbit-rabbit" ]]; then
  rapydo create prj -s celery -s rabbit --auth ${AUTH} --frontend no;
elif [[ "$TEMPLATE" == "celery-rabbit-redis" ]]; then
  rapydo create prj -s celery -s rabbit -s redis --auth ${AUTH} --frontend no;
elif [[ "$TEMPLATE" == "celery-rabbit-mongo" ]]; then
  rapydo create prj -s celery -s rabbit -s mongo --auth ${AUTH} --frontend no;
elif [[ "$TEMPLATE" == "celery-redis-redis" ]]; then
  rapydo create prj -s celery -s redis --auth ${AUTH} --frontend no;
elif [[ "$TEMPLATE" == "celery-redis-mongo" ]]; then
  rapydo create prj -s celery -s redis -s mongo --auth ${AUTH} --frontend no;


elif [[ "$TEMPLATE" == "extra" ]]; then
  rapydo create prjbase --auth ${AUTH} --frontend no;
  rapydo create prj --current --extend prjbase -s ftp -s pushpin -s bot --auth ${AUTH} --frontend no --add-optionals -e AUTH_FORCE_FIRST_PASSWORD_CHANGE=1 -e AUTH_MAX_PASSWORD_VALIDITY=10 -e AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=30 -e AUTH_MAX_LOGIN_ATTEMPTS=5 -e AUTH_LOGIN_BAN_TIME=10 -e AUTH_SECOND_FACTOR_AUTHENTICATION=TOTP;


else
  echo "Unknown template: ${TEMPLATE}";
  exit 1;
fi

git remote add origin https://your_remote_git/your_project.git