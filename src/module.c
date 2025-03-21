#include <valkeymodule.h>
#include <assert.h>
#include "vk_ldap.h"

int test_ldap_auth(ValkeyModuleCtx* ctx, ValkeyModuleString** argv, int argc) {
    if (argc != 3) return ValkeyModule_WrongArity(ctx);

    char *err = NULL;
    LDAPConn *lpconn = vk_ldap_init("ldap://ldap", &err);

    if (lpconn == NULL) {
        assert(err != NULL);
        ValkeyModule_Log(ctx, "warning", "Failed to initialize ldap connection: %s", err);
        return VALKEYMODULE_ERR;
    }

    const char *username = ValkeyModule_StringPtrLen(argv[1], NULL);
    const char *password = ValkeyModule_StringPtrLen(argv[2], NULL);
    char *user_dn;
    asprintf(&user_dn, "CN=%s,OU=devops,DC=valkey,DC=io", username);

    err = NULL;
    int ret = vk_ldap_auth(lpconn, user_dn, password, &err);
    free(user_dn);

    if (ret != 0) {
        ValkeyModule_Log(ctx, "warning", "ldap bind failed: %s", err);
        ValkeyModule_ReplyWithErrorFormat(ctx, "Authentication failed: %s", err);
        return VALKEYMODULE_OK;
    }

    ValkeyModule_Log(ctx, "info", "User %s bind successful", username);

    vk_ldap_destroy(lpconn);

    ValkeyModule_ReplyWithSimpleString(ctx, "OK");

    return VALKEYMODULE_OK;
}

int ValkeyModule_OnLoad(ValkeyModuleCtx* ctx, ValkeyModuleString** argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    VALKEYMODULE_NOT_USED(argc);

    if (ValkeyModule_Init(ctx, "ldap", 1, VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_CreateCommand(ctx, "ldap.test_auth", test_ldap_auth, "readonly", 0, 0, 0) ==
        VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    return VALKEYMODULE_OK;
}

int ValkeyModule_OnUnload(ValkeyModuleCtx* ctx) {
    VALKEYMODULE_NOT_USED(ctx);
    return VALKEYMODULE_OK;
}
