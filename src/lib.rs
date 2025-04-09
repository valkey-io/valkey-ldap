mod vkldap;

use valkey_module::{Context, VALKEY_OK, ValkeyError, ValkeyResult, ValkeyString, valkey_module};
use vkldap::VkLdapContext;

fn test_ldap_auth(ctx: &Context, args: Vec<ValkeyString>) -> ValkeyResult {
    if args.len() < 2 {
        return Err(ValkeyError::WrongArity);
    }

    let username = &args[1];
    let bind_dn = format!("CN={username},OU=devops,DC=valkey,DC=io");

    let mut ldap_ctx = VkLdapContext::new(ctx, "ldap://ldap")?;

    ldap_ctx.bind(&bind_dn, &args[2].to_string())?;

    VALKEY_OK
}

valkey_module! {
    name: "valkey-ldap",
    version: 1,
    allocator: (valkey_module::alloc::ValkeyAlloc, valkey_module::alloc::ValkeyAlloc),
    data_types: [],
    commands: [
        ["ldap.test_auth", test_ldap_auth, "readonly", 0, 0, 0],
    ],
}
