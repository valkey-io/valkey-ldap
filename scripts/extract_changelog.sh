#!/bin/bash


while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done


VERSION="$1"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

awk -v pattern="^## \\\[$VERSION\\\]" '$0 ~ pattern {flag=1; next} flag && $0 ~ "^## \\[" {flag=0} flag {print}' CHANGELOG.md

