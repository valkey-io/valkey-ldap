mod configs;
mod vkldap;

use std::os::raw::c_int;

use valkey_module::{
    AUTH_HANDLED, AUTH_NOT_HANDLED, Context, Status, ValkeyError, ValkeyString,
    configuration::ConfigurationFlags, logging::standard_log_implementation, valkey_module,
};
use vkldap::vk_ldap_bind;

fn ldap_auth_callback(
    ctx: &Context,
    user: ValkeyString,
    pass: ValkeyString,
) -> Result<c_int, ValkeyError> {
    if !configs::is_auth_enabled(ctx) {
        return Ok(AUTH_NOT_HANDLED);
    }

    match vk_ldap_bind(&ctx, user.to_string().as_str(), pass.to_string().as_str()) {
        Ok(_) => match ctx.authenticate_client_with_acl_user(&user) {
            Status::Ok => {
                ctx.log_notice(&format!("successfully authenticated user: {}", user));
                Ok(AUTH_HANDLED)
            }
            Status::Err => Err(ValkeyError::Str("Failed to authenticate with ACL")),
        },
        Err(e) => Err(ValkeyError::from(e)),
    }
}

fn initializer(_: &Context, _args: &[ValkeyString]) -> Status {
    let res = standard_log_implementation::setup();
    if let Err(_) = res {
        return Status::Err;
    }
    Status::Ok
}

valkey_module! {
    name: "ldap",
    version: 1,
    allocator: (valkey_module::alloc::ValkeyAlloc, valkey_module::alloc::ValkeyAlloc),
    data_types: [],
    init: initializer,
    auth: [
        ldap_auth_callback
    ],
    commands: [
    ],
    configurations: [
        i64: [],
        string: [
            [
                "servers",
                &*configs::LDAP_SERVER_LIST,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                Some(Box::new(configs::ldap_server_list_set_callback))
            ],
            [
                "bind_dn_prefix",
                &*configs::LDAP_BIND_DN_PREFIX,
                "cn=",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
            [
                "bind_dn_suffix",
                &*configs::LDAP_BIND_DN_SUFFIX,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
            [
                "tls_ca_cert_path",
                &*configs::LDAP_TLS_CA_CERT_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
            [
                "tls_cert_path",
                &*configs::LDAP_TLS_CERT_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
            [
                "tls_key_path",
                &*configs::LDAP_TLS_KEY_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
        ],
        bool: [
            ["use_starttls", &*configs::LDAP_USE_STARTTLS, false, ConfigurationFlags::DEFAULT, None],
            ["auth_enabled", &*configs::LDAP_AUTH_ENABLED, true, ConfigurationFlags::DEFAULT, None]
        ],
        enum: [],
        module_args_as_configuration: true,
    ]
}
