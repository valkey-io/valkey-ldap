#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

cargo build || exit 1

DOCKER_COMPOSE_RUNNING=`docker compose ls --filter name=valkey-ldap -q && true`

STOP_SERVERS=""

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
