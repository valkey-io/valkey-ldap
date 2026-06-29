#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done
pushd scripts/docker > /dev/null


version=${1:-9.0}


cat <<EOF > "Dockerfile-valkey-ldap-${version}"
FROM debian:12

VOLUME [ "/valkey-ldap" ]

RUN apt update
RUN apt install -y openssl git make clang build-essential libssl-dev

RUN git clone -b ${version} --single-branch https://github.com/valkey-io/valkey.git
RUN cd valkey && \\
    make -j\$(nproc) SANITIZER=address OPTIMIZATION=-g3 && \\
    make install

WORKDIR /valkey-ldap

CMD [ "valkey-server", "./valkey.conf" ]
EOF

popd > /dev/null
