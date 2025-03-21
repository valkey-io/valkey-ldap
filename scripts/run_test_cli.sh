#!/bin/bash

if [ `basename $(pwd)` != "valkey-ldap" ]; then
    echo "ERROR: run this script from the repo root directory"
    exit 1
fi

DOCKER_COMPOSE_RUNNING=`docker compose ls --filter name=valkey-ldap -q && true`

STOP_SERVERS=

if [ -z $DOCKER_COMPOSE_RUNNING ]; then
    ./scripts/start_valkey_ldap.sh
    STOP_SERVERS=true
fi

# Wait for valkey-server to be online
while true; do
    nc -z localhost 6379 && break
done

docker exec -ti valkey valkey-cli

if [ ! -z $STOP_SERVERS ]; then
    ./scripts/stop_valkey_ldap.sh
fi
