#!/bin/bash

if [ `basename $(pwd)` != "valkey-ldap" ]; then
    echo "ERROR: run this script from the repo root directory"
    exit 1
fi

DOCKER_COMPOSE_RUNNING=`docker compose ls --filter name=valkey-ldap -q && true`

if [ ! -z $DOCKER_COMPOSE_RUNNING ]; then
    echo "The LDAP and Valkey servers are already running"
else
    pushd scripts/docker > /dev/null

    docker compose up > /tmp/valkey-ldap.log 2>&1 &
    DOCKER_COMPOSE_PID=$!

    popd > /dev/null
fi

# Wait for valkey-server to be online
while true; do
    nc -z localhost 6379 && break
done

# Wait for ldap server to be online
while true; do
    nc -z localhost 389 && break
done

