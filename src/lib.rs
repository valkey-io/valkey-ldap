mod auth;
mod configs;
mod vkldap;

use auth::ldap_auth_blocking_callback;

use valkey_module::{
    Context, Status, ValkeyString, configuration::ConfigurationFlags,
    logging::standard_log_implementation, valkey_module,
};

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
        ldap_auth_blocking_callback
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
            [
                "search_base",
                &*configs::LDAP_SEARCH_BASE,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
            [
                "search_filter",
                &*configs::LDAP_SEARCH_FILTER,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
            [
                "search_attribute",
                &*configs::LDAP_SEARCH_ATTRIBUTE,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
            [
                "search_bind_dn",
                &*configs::LDAP_SEARCH_BIND_DN,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
            [
                "search_bind_passwd",
                &*configs::LDAP_SEARCH_BIND_PASSWD,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
            [
                "search_dn_attribute",
                &*configs::LDAP_SEARCH_DN_ATTRIBUTE,
                "entryDN",
                ConfigurationFlags::DEFAULT,
                None,
                None
            ],
        ],
        bool: [
            ["use_starttls", &*configs::LDAP_USE_STARTTLS, false, ConfigurationFlags::DEFAULT, None],
            ["auth_enabled", &*configs::LDAP_AUTH_ENABLED, true, ConfigurationFlags::DEFAULT, None],
        ],
        enum: [
            ["auth_mode", &*configs::LDAP_AUTH_MODE, configs::LdapAuthMode::Bind, ConfigurationFlags::DEFAULT, None],
            ["search_scope", &*configs::LDAP_SEARCH_SCOPE, configs::LdapSearchScope::SubTree, ConfigurationFlags::DEFAULT, None],
        ],
        module_args_as_configuration: true,
    ]
}
