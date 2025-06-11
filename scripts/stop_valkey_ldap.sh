#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

DOCKER_COMPOSE_RUNNING=`docker compose ls --filter name=valkey-ldap -q`

if [ -z $DOCKER_COMPOSE_RUNNING ]; then
    echo "ERROR: valkey and ldap containers are not running"
    exit 1
fi

pushd scripts/docker > /dev/null

docker compose --profile valkey-7.2 down
docker compose --profile valkey-8.0 down
docker compose --profile valkey-8.1 down
docker compose rm -f valkey-7.2 valkey-8.0 valkey-8.1

popd > /dev/null
