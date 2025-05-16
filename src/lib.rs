mod auth;
mod commands;
mod configs;
mod version;
mod vkldap;

use auth::ldap_auth_blocking_callback;
use commands::ldap_status_command;
use log::debug;
use version::module_version;
use vkldap::{start_ldap_failure_detector, stop_ldap_failure_detector};

use valkey_module::{
    Context, Status, ValkeyString, configuration::ConfigurationFlags,
    logging::standard_log_implementation, valkey_module,
};

fn initializer(_: &Context, _args: &[ValkeyString]) -> Status {
    let res = standard_log_implementation::setup();
    if let Err(_) = res {
        return Status::Err;
    }

    start_ldap_failure_detector();

    Status::Ok
}

fn deinitializer(_: &Context) -> Status {
    if let Err(err) = stop_ldap_failure_detector() {
        debug!("{err}");
        return Status::Err;
    }
    Status::Ok
}

valkey_module! {
    name: "ldap",
    version: module_version(),
    allocator: (valkey_module::alloc::ValkeyAlloc, valkey_module::alloc::ValkeyAlloc),
    data_types: [],
    init: initializer,
    deinit: deinitializer,
    auth: [
        ldap_auth_blocking_callback
    ],
    commands: [
        ["ldap.status", ldap_status_command, "readonly", 0, 0, 0],
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
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "bind_dn_suffix",
                &*configs::LDAP_BIND_DN_SUFFIX,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "tls_ca_cert_path",
                &*configs::LDAP_TLS_CA_CERT_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "tls_cert_path",
                &*configs::LDAP_TLS_CERT_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "tls_key_path",
                &*configs::LDAP_TLS_KEY_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "search_base",
                &*configs::LDAP_SEARCH_BASE,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "search_filter",
                &*configs::LDAP_SEARCH_FILTER,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "search_attribute",
                &*configs::LDAP_SEARCH_ATTRIBUTE,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "search_bind_dn",
                &*configs::LDAP_SEARCH_BIND_DN,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "search_bind_passwd",
                &*configs::LDAP_SEARCH_BIND_PASSWD,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "search_dn_attribute",
                &*configs::LDAP_SEARCH_DN_ATTRIBUTE,
                "entryDN",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
        ],
        bool: [
            [
                "use_starttls",
                &*configs::LDAP_USE_STARTTLS,
                false,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "auth_enabled",
                &*configs::LDAP_AUTH_ENABLED,
                true,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
        ],
        enum: [
            [
                "auth_mode",
                &*configs::LDAP_AUTH_MODE,
                configs::LdapAuthMode::Bind,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
            [
                "search_scope",
                &*configs::LDAP_SEARCH_SCOPE,
                configs::LdapSearchScope::SubTree,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::refresh_config_cache))
            ],
        ],
        module_args_as_configuration: true,
    ]
}
