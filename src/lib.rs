mod auth;
mod commands;
mod configs;
mod version;
mod vkldap;

use log::error;
use valkey_module::{
    Context, Status, ValkeyGILGuard, ValkeyString, configuration::ConfigurationFlags,
    logging::standard_log_implementation, valkey_module,
};

use auth::ldap_auth_blocking_callback;
use commands::ldap_status_command;
use version::module_version;
use vkldap::failure_detector;
use vkldap::scheduler;

fn initializer(ctx: &Context, _args: &[ValkeyString]) -> Status {
    ctx.log_debug("initializing LDAP module");

    let res = standard_log_implementation::setup();
    if let Err(err) = res {
        ctx.log_warning(format!("failed to setup log: {err}").as_str());
    }

    scheduler::start_job_scheduler();
    failure_detector::start_failure_detector_thread();

    configs::refresh_ldap_settings_cache(ctx);
    configs::refresh_connection_settings_cache(ctx);

    let server_list = configs::LDAP_SERVER_LIST.lock(ctx).to_string_lossy();
    if let Err(err) = configs::process_server_list(server_list) {
        ctx.log_warning(format!("failed to load server list: {err}").as_str());
    }

    Status::Ok
}

fn deinitializer(ctx: &Context) -> Status {
    ctx.log_debug("shutting down LDAP module");

    if let Err(err) = failure_detector::shutdown_failure_detector_thread() {
        error!("{err}");
        return Status::Err;
    }

    if let Err(err) = vkldap::clear_server_list() {
        error!("{err}");
        return Status::Err;
    }

    if let Err(err) = scheduler::stop_job_scheduler() {
        error!("{err}");
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
        i64: [
            [
                "connection_pool_size",
                &*configs::LDAP_CONNECTION_POOL_SIZE,
                2,
                1,
                8192,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                "failure_detector_interval",
                &*configs::LDAP_FAILURE_DETECTOR_INTERVAL,
                1,
                0,
                std::i64::MAX,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::failure_detector_interval_changed))
            ],
            [
                "timeout_connection",
                &*configs::LDAP_TIMEOUT_CONNECTION,
                10,
                0,
                std::i64::MAX,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                "timeout_ldap_operation",
                &*configs::LDAP_TIMEOUT_LDAP_OPERATION,
                10,
                0,
                std::i64::MAX,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ]
        ],
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
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                "bind_dn_suffix",
                &*configs::LDAP_BIND_DN_SUFFIX,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                "tls_ca_cert_path",
                &*configs::LDAP_TLS_CA_CERT_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                "tls_cert_path",
                &*configs::LDAP_TLS_CERT_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                "tls_key_path",
                &*configs::LDAP_TLS_KEY_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                "search_base",
                &*configs::LDAP_SEARCH_BASE,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                "search_filter",
                &*configs::LDAP_SEARCH_FILTER,
                "objectClass=*",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                "search_attribute",
                &*configs::LDAP_SEARCH_ATTRIBUTE,
                "uid",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                "search_bind_dn",
                &*configs::LDAP_SEARCH_BIND_DN,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                "search_bind_passwd",
                &*configs::LDAP_SEARCH_BIND_SHADOW_PASSWD,
                "",
                ConfigurationFlags::SENSITIVE,
                None,
                Some(Box::new(configs::on_password_config_set::<ValkeyString, ValkeyGILGuard<ValkeyString>>))
            ],
            [
                "search_dn_attribute",
                &*configs::LDAP_SEARCH_DN_ATTRIBUTE,
                "entryDN",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
        ],
        bool: [
            [
                "use_starttls",
                &*configs::LDAP_USE_STARTTLS,
                false,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                "auth_enabled",
                &*configs::LDAP_AUTH_ENABLED,
                true,
                ConfigurationFlags::DEFAULT,
                None
            ],
        ],
        enum: [
            [
                "auth_mode",
                &*configs::LDAP_AUTH_MODE,
                configs::LdapAuthMode::Bind,
                ConfigurationFlags::DEFAULT,
                None
            ],
            [
                "search_scope",
                &*configs::LDAP_SEARCH_SCOPE,
                configs::LdapSearchScope::SubTree,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
        ],
        module_args_as_configuration: false,
    ]
}
