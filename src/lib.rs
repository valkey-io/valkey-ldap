mod auth;
mod commands;
mod configs;
mod logging;
mod version;
mod vkldap;

use log::error;
use valkey_module::{
    Context, Status, ValkeyString, configuration::ConfigurationFlags, valkey_module,
};

use auth::ldap_auth_blocking_callback;
use logging::standard_log_implementation;
use version::module_version;
use vkldap::failure_detector;
use vkldap::scheduler;

fn initializer(ctx: &Context, _args: &[ValkeyString]) -> Status {
    ctx.log_debug("initializing LDAP module");

    let res = standard_log_implementation::setup_for_context(ctx);
    if let Err(err) = res {
        ctx.log_warning(format!("failed to setup log: {err}").as_str());
    }

    scheduler::start_job_scheduler();
    failure_detector::start_failure_detector_thread();

    // Wait for scheduler to be ready (with timeout)
    let mut attempts = 0;
    while !scheduler::is_scheduler_ready() && attempts < 100 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        attempts += 1;
    }

    if !scheduler::is_scheduler_ready() {
        ctx.log_warning("scheduler not ready after timeout");
        return Status::Err;
    }

    // Reset context to clear any stale state from previous module load
    if let Err(err) = vkldap::reset_context() {
        ctx.log_warning(format!("failed to reset context: {err}").as_str());
    }

    // Debug: check search_base value from config
    let search_base_value = configs::LDAP_SEARCH_BASE.lock(ctx).to_string_lossy();
    ctx.log_debug(format!("search_base from config: '{}'", search_base_value).as_str());

    // Use blocking versions during initialization to avoid async scheduler delays
    configs::refresh_ldap_settings_cache_blocking(ctx);
    configs::refresh_connection_settings_cache_blocking(ctx);

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

    // Teardown the logger to free the thread-safe context
    standard_log_implementation::teardown();

    Status::Ok
}

// Configuration name helper.
//
// A Valkey/Redis module exposes its configs as `<module-name>.<config-name>`.
// When valkey-ldap runs standalone the module name is `ldap`, so the configs
// are `ldap.servers`, `ldap.search_base`, etc.
//
// When this crate is embedded into another module (the `embed` feature, used
// by FalkorDB Enterprise) the host module owns the name. Redis does not allow
// a `.` inside a module config name, so a true `<host>.ldap.<name>` subkey is
// impossible; instead each name is prefixed with `ldap_` to keep the LDAP
// settings grouped under a common, glob-friendly prefix. The host then exposes
// them as `<host>.ldap_<name>` (e.g. `falkordbe.ldap_servers`).
#[cfg(feature = "embed")]
macro_rules! cfg_name {
    ($n:literal) => {
        concat!("ldap_", $n)
    };
}

#[cfg(not(feature = "embed"))]
macro_rules! cfg_name {
    ($n:literal) => {
        $n
    };
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
    commands: [],
    configurations: [
        i64: [
            [
                cfg_name!("connection_pool_size"),
                &*configs::LDAP_CONNECTION_POOL_SIZE,
                2,
                1,
                8192,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                cfg_name!("failure_detector_interval"),
                &*configs::LDAP_FAILURE_DETECTOR_INTERVAL,
                1,
                0,
                std::i64::MAX,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::failure_detector_interval_changed))
            ],
            [
                cfg_name!("timeout_connection"),
                &*configs::LDAP_TIMEOUT_CONNECTION,
                10,
                0,
                std::i64::MAX,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                cfg_name!("timeout_ldap_operation"),
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
                cfg_name!("servers"),
                &*configs::LDAP_SERVER_LIST,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                Some(Box::new(configs::ldap_server_list_set_callback))
            ],
            [
                cfg_name!("bind_dn_prefix"),
                &*configs::LDAP_BIND_DN_PREFIX,
                "cn=",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("bind_dn_suffix"),
                &*configs::LDAP_BIND_DN_SUFFIX,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("tls_ca_cert_path"),
                &*configs::LDAP_TLS_CA_CERT_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                cfg_name!("tls_cert_path"),
                &*configs::LDAP_TLS_CERT_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                cfg_name!("tls_key_path"),
                &*configs::LDAP_TLS_KEY_PATH,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                cfg_name!("search_base"),
                &*configs::LDAP_SEARCH_BASE,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("search_filter"),
                &*configs::LDAP_SEARCH_FILTER,
                "objectClass=*",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("search_attribute"),
                &*configs::LDAP_SEARCH_ATTRIBUTE,
                "uid",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("search_bind_dn"),
                &*configs::LDAP_SEARCH_BIND_DN,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("search_bind_passwd"),
                &*configs::LDAP_SEARCH_BIND_PASSWD,
                "",
                ConfigurationFlags::SENSITIVE | ConfigurationFlags::HIDDEN,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("search_dn_attribute"),
                &*configs::LDAP_SEARCH_DN_ATTRIBUTE,
                "entryDN",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("groups_search_base"),
                &*configs::LDAP_GROUPS_SEARCH_BASE,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("groups_filter"),
                &*configs::LDAP_GROUPS_FILTER,
                "objectClass=groupOfNames",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("groups_member_attribute"),
                &*configs::LDAP_GROUPS_MEMBER_ATTRIBUTE,
                "member",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("groups_name_attribute"),
                &*configs::LDAP_GROUPS_NAME_ATTRIBUTE,
                "cn",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("groups_rules_attribute"),
                &*configs::LDAP_GROUPS_RULES_ATTRIBUTE,
                "valkeyACL",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("group_acl_user_map"),
                &*configs::LDAP_GROUP_TO_ACL_USER_MAP,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("group_acl_rules_map"),
                &*configs::LDAP_GROUP_TO_ACL_RULES_MAP,
                "",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("default_acl_rules"),
                &*configs::LDAP_DEFAULT_ACL_RULES,
                "on resetpass",
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
            [
                cfg_name!("exempted_users_regex"),
                &*configs::LDAP_EXEMPTED_USERS_REGEX,
                "",
                ConfigurationFlags::DEFAULT,
                None,
                Some(Box::new(configs::exempted_users_regex_set_callback))
            ],
        ],
        bool: [
            [
                cfg_name!("use_starttls"),
                &*configs::LDAP_USE_STARTTLS,
                false,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                cfg_name!("tls_skip_verify"),
                &*configs::LDAP_TLS_SKIP_VERIFY,
                false,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_connection_setting_change))
            ],
            [
                cfg_name!("acl_fallback_enabled"),
                &*configs::LDAP_ACL_FALLBACK_ENABLED,
                false,
                ConfigurationFlags::DEFAULT,
                None
            ],
            [
                cfg_name!("return_auth_errors"),
                &*configs::LDAP_RETURN_AUTH_ERRORS,
                false,
                ConfigurationFlags::DEFAULT,
                None
            ],
        ],
        enum: [
            [
                cfg_name!("auth_mode"),
                &*configs::LDAP_AUTH_MODE,
                configs::LdapAuthMode::Bind,
                ConfigurationFlags::DEFAULT,
                None
            ],
            [
                cfg_name!("search_scope"),
                &*configs::LDAP_SEARCH_SCOPE,
                configs::LdapSearchScope::SubTree,
                ConfigurationFlags::DEFAULT,
                Some(Box::new(configs::on_ldap_setting_change))
            ],
        ],
        module_args_as_configuration: false,
    ]
}
