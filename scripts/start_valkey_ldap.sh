#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

cargo build

DOCKER_COMPOSE_RUNNING=`docker compose ls --filter name=valkey-ldap -q && true`

if [ ! -z $DOCKER_COMPOSE_RUNNING ]; then
    echo "The LDAP and Valkey servers are already running"
else
    pushd scripts/docker > /dev/null

    docker compose up -d --wait
    docker compose logs -f > /tmp/valkey-ldap.log 2>&1 &

    popd > /dev/null
fi

# Wait for valkey-server to be online
while true; do
    echo "Waiting for Valkey server"
    sleep 1
    nc -z localhost 6379 && break
done

# Wait for ldap server to be online
while true; do
    echo "Waiting for LDAP server"
    sleep 1
    nc -z localhost 389 && break
done

./scripts/populate_ldap.sh
