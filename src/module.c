#include <stdio.h>
#define LDAP_DEPRECATED 1

#include <ldap.h>
#include <valkeymodule.h>

int test_ldap_auth(ValkeyModuleCtx* ctx, ValkeyModuleString** argv, int argc) {
    LDAP* ld;
    int version = LDAP_VERSION3;

    if (argc != 3) return ValkeyModule_WrongArity(ctx);

    if (ldap_initialize(&ld, "ldap://ldap")) {
        ValkeyModule_Log(ctx, "warning", "failed to initialize ldap connection");
        return VALKEYMODULE_ERR;
    }

    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    const char *username = ValkeyModule_StringPtrLen(argv[1], NULL);
    const char *password = ValkeyModule_StringPtrLen(argv[2], NULL);
    char *user_dn;
    asprintf(&user_dn, "CN=%s,OU=devops,DC=valkey,DC=io", username);

    int rc = ldap_bind_s(ld, user_dn, password, LDAP_AUTH_SIMPLE);
    free(user_dn);

    if (rc != LDAP_SUCCESS) {
        ValkeyModule_Log(ctx, "warning", "ldap bind failed: %s", ldap_err2string(rc));
        ValkeyModule_ReplyWithErrorFormat(ctx, "Authentication failed: %s", ldap_err2string(rc));
        return VALKEYMODULE_OK;
    }

    ValkeyModule_Log(ctx, "info", "bind successful: rc=%d", rc);

    ldap_unbind(ld);

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
