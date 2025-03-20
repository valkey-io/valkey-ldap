#define LDAP_DEPRECATED 1

#include <ldap.h>
#include <valkeymodule.h>

int test_ldap_auth(ValkeyModuleCtx* ctx) {
    LDAP* ld;
    int version = LDAP_VERSION3;

    if (ldap_initialize(&ld, "ldap://localhost")) {
        ValkeyModule_Log(ctx, "warning", "failed to initialize ldap connection");
        return 0;
    }

    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    int rc = ldap_bind_s(ld, "CN=user,OU=devops,DC=valkey,DC=io", "user1@123", LDAP_AUTH_SIMPLE);

    if (rc != LDAP_SUCCESS) {
        ValkeyModule_Log(ctx, "warning", "ldap bind failed: %s", ldap_err2string(rc));
        return 0;
    }

    ValkeyModule_Log(ctx, "info", "bind successful: rc=%d", rc);

    ldap_unbind(ld);

    return 1;
}

int ValkeyModule_OnLoad(ValkeyModuleCtx* ctx, ValkeyModuleString** argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    VALKEYMODULE_NOT_USED(argc);

    if (ValkeyModule_Init(ctx, "ldap", 1, VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    test_ldap_auth(ctx);

    return VALKEYMODULE_OK;
}

int ValkeyModule_OnUnload(ValkeyModuleCtx* ctx) {
    VALKEYMODULE_NOT_USED(ctx);
    return VALKEYMODULE_OK;
}
