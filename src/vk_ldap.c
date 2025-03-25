#include "vk_ldap.h"

#include <stdio.h>
#include <stdlib.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

typedef struct LDAPConn {
    LDAP* ld;
} LDAPConn;

LDAPConn* vk_ldap_init(const char* url, char** err) {
    LDAPConn* lpconn = (LDAPConn*)malloc(sizeof(*lpconn));
    int ret = ldap_initialize(&lpconn->ld, url);
    if (ret != LDAP_SUCCESS) {
        *err = ldap_err2string(ret);
        return NULL;
    }

    int version = LDAP_VERSION3;
    ldap_set_option(lpconn->ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    return lpconn;
}

void vk_ldap_destroy(LDAPConn* lpconn) {
    ldap_unbind(lpconn->ld);
    lpconn->ld = NULL;
    free(lpconn);
}

int vk_ldap_auth(LDAPConn* lpconn, const char* user_dn, const char* pass, char** err) {
    int ret = ldap_bind_s(lpconn->ld, user_dn, pass, LDAP_AUTH_SIMPLE);

    if (ret != LDAP_SUCCESS) {
        *err = ldap_err2string(ret);
        return 1;
    }

    return 0;
}
