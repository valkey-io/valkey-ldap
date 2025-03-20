#!/bin/bash

# Wait for ldap server to be online
while true; do
    nc -z localhost 389 && break
done

ADMIN_PASSWD=admin123!
DC="dc=valkey,dc=io"
ADMIN_DN="cn=admin,${DC}"

ldapadd -x -w ${ADMIN_PASSWD} -D ${ADMIN_DN} << EOF
dn: ou=devops,${DC}
objectClass: organizationalUnit
ou: devops

dn: ou=appdev,${DC}
objectClass: organizationalUnit
ou: appdev
EOF

# Create User accounts.
ldapadd -x -w ${ADMIN_PASSWD} -D ${ADMIN_DN} << EOF
dn: cn=user1,ou=devops,${DC}
objectClass: person
cn: user1
sn: User1
userPassword: user1@123

dn: cn=charlie,ou=appdev,${DC}
objectClass: inetOrgPerson
cn: charlie
sn: Charlie
uid: charlie
userPassword: Charlie@123
EOF

# # Create Groups
# ldapadd -x -w ${ADMIN_PASSWD} -D ${ADMIN_DN} << EOF
# # Group: appdev-team
# dn: cn=appdev-team,dc=example,dc=in
# objectClass: top
# objectClass: groupOfNames
# cn: appdev-team
# description: App Development Team
# member: cn=amrutha,ou=devops,dc=example,dc=in
# member: cn=charlie,ou=appdev,dc=example,dc=in
#
# # Group: devops-team
# dn: cn=devops-team,dc=example,dc=in
# objectClass: top
# objectClass: groupOfNames
# cn: devops-team
# description: DevOps Team
# member: cn=amrutha,ou=devops,dc=example,dc=in
# member: cn=amit,ou=appdev,dc=example,dc=in
# EOF
#
# # Modify and apply MemberOf attribute to Users in Groups.
# ldapadd -x -w ${ADMIN_PASSWD} -D ${ADMIN_DN} << EOF
# dn: cn=amrutha,ou=devops,dc=example,dc=in
# changetype: modify
# add: memberOf
# memberOf: cn=devops-team,dc=example,dc=in
#
# dn: cn=amit,ou=appdev,dc=example,dc=in
# changetype: modify
# add: memberOf
# memberOf: cn=appdev-team,dc=example,dc=in
#
# dn: cn=charile,ou=appdev,dc=example,dc=in
# changetype: modify
# add: memberOf
# memberOf: cn=devops-team,dc=example,dc=in
# EOF
