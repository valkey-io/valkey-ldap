#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

if [ -d scripts/docker/certs ]; then
    echo "Certificates were already generated"
    exit 0
fi

mkdir -p scripts/docker/certs
cd scripts/docker/certs

# CA Certificate
openssl req -x509 -new -nodes -newkey rsa:2048 -keyout valkey-ldap-ca.key -sha256 -days 1825 -out valkey-ldap-ca.crt -subj /CN='valkey-ldap-ca'

# Diffie-Hellman parameters
openssl dhparam -out dhparam.pem 2048

# LDAP server certificate
openssl req -newkey rsa:2048 -nodes -keyout valkey-ldap.key -out valkey-ldap.csr -subj /CN=ldap -addext subjectAltName=DNS:ldap
openssl x509 -req -in valkey-ldap.csr -copy_extensions copy -CA valkey-ldap-ca.crt -CAkey valkey-ldap-ca.key -CAcreateserial -out valkey-ldap.crt -days 365 -sha256

# LDAP client certificate
openssl req -newkey rsa:2048 -nodes -keyout valkey-ldap-client.key -out valkey-ldap-client.csr -subj /CN=valkey -addext subjectAltName=DNS:valkey
openssl x509 -req -in valkey-ldap-client.csr -copy_extensions copy -CA valkey-ldap-ca.crt -CAkey valkey-ldap-ca.key -CAcreateserial -out valkey-ldap-client.crt -days 365 -sha256

rm -f *.csr *.srl

# Move client certificates to test directory
mv valkey-ldap-client.* ../../../test/
