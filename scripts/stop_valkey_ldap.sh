#!/bin/bash

if [ `basename $(pwd)` != "valkey-ldap" ]; then
    echo "ERROR: run this script from the repo root directory"
    exit 1
fi

DOCKER_COMPOSE_RUNNING=`docker compose ls --filter name=valkey-ldap -q`

if [ -z $DOCKER_COMPOSE_RUNNING ]; then
    echo "ERROR: valkey and ldap containers are not running"
    exit 1
fi

pushd scripts/docker > /dev/null

docker compose down

popd > /dev/null
