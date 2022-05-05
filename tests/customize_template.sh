#!/bin/bash
set -e

TEMPLATE=$1

if [[ "$TEMPLATE" == "celery-rabbit-redis" ]]; then
  rapydo add task test_task;
elif [[ "$TEMPLATE" == "celery-redis-redis" ]]; then
  rapydo add task test_task;
fi
