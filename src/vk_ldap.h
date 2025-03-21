#ifndef _VK_LDAP_H_
#define _VK_LDAP_H_

typedef struct LDAPConn LDAPConn;

LDAPConn* vk_ldap_init(const char *url, char **err);
void vk_ldap_destroy(LDAPConn *lpconn);
int vk_ldap_auth(LDAPConn* lpconn, const char* user_dn, const char* pass, char **err);

#endif