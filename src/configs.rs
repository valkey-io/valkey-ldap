use std::collections::LinkedList;

use lazy_static::lazy_static;
use valkey_module::{
    ConfigurationValue, ValkeyError, ValkeyGILGuard, ValkeyLockIndicator, ValkeyString,
    configuration::ConfigurationContext,
};

use crate::vkldap::failure_detector;
use crate::vkldap::settings::VkLdapSettings;
use crate::vkldap::{self, settings::VkConnectionSettings};
use log::{debug, error};
use url::Url;

macro_rules! enum_configuration2 {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident = ($sname:expr, $val:expr),)*
    }) => {
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $vname = $val,)*
        }

        impl std::convert::TryFrom<i32> for $name {
            type Error = valkey_module::ValkeyError;

            fn try_from(v: i32) -> Result<Self, Self::Error> {
                match v {
                    $(x if x == $name::$vname as i32 => Ok($name::$vname),)*
                    _ => Err(valkey_module::ValkeyError::Str("Value is not supported")),
                }
            }
        }

        impl std::convert::From<$name> for i32 {
            fn from(val: $name) -> Self {
                val as i32
            }
        }

        impl valkey_module::configuration::EnumConfigurationValue for $name {
            fn get_options(&self) -> (Vec<String>, Vec<i32>) {
                (vec![$($sname.to_string(),)*], vec![$($val,)*])
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                match self {
                    $($name::$vname => $name::$vname,)*
                }
            }
        }
    }
}

enum_configuration2! {
    #[derive(PartialEq)]
    pub enum LdapAuthMode {
        Bind = ("bind", 1),
        SearchAndBind = ("search+bind", 2),
    }
}

enum_configuration2! {
    #[derive(PartialEq)]
    pub enum LdapSearchScope {
        Base = ("base", 1),
        OneLevel = ("one", 2),
        SubTree = ("sub", 3),
    }
}

lazy_static! {
    pub static ref LDAP_SERVER_LIST: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_BIND_DN_PREFIX: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_BIND_DN_SUFFIX: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_TLS_CA_CERT_PATH: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_TLS_CERT_PATH: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_TLS_KEY_PATH: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_USE_STARTTLS: ValkeyGILGuard<bool> = ValkeyGILGuard::default();
    pub static ref LDAP_AUTH_ENABLED: ValkeyGILGuard<bool> = ValkeyGILGuard::default();
    pub static ref LDAP_AUTH_MODE: ValkeyGILGuard<LdapAuthMode> =
        ValkeyGILGuard::new(LdapAuthMode::Bind);
    pub static ref LDAP_SEARCH_BASE: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_SEARCH_SCOPE: ValkeyGILGuard<LdapSearchScope> =
        ValkeyGILGuard::new(LdapSearchScope::SubTree);
    pub static ref LDAP_SEARCH_FILTER: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_SEARCH_ATTRIBUTE: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_SEARCH_BIND_DN: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_SEARCH_BIND_SHADOW_PASSWD: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_SEARCH_DN_ATTRIBUTE: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
    pub static ref LDAP_CONNECTION_POOL_SIZE: ValkeyGILGuard<i64> = ValkeyGILGuard::new(2);
    pub static ref LDAP_FAILURE_DETECTOR_INTERVAL: ValkeyGILGuard<i64> = ValkeyGILGuard::new(1);
}

lazy_static! {
    static ref LDAP_SEARCH_BIND_PASSWD: ValkeyGILGuard<ValkeyString> =
        ValkeyGILGuard::new(ValkeyString::create(None, ""));
}

pub fn refresh_ldap_settings_cache<T: ValkeyLockIndicator>(ctx: &T) {
    let settings = VkLdapSettings::new(
        get_bind_dn_prefix(ctx),
        get_bind_dn_suffix(ctx),
        get_search_base(ctx),
        get_search_scope(ctx),
        get_search_filter(ctx),
        get_search_attribute(ctx),
        get_search_bind_dn(ctx),
        get_search_bind_passwd(ctx),
        get_search_dn_attribute(ctx),
    );
    vkldap::refresh_ldap_settings(settings);
}

pub fn refresh_connection_settings_cache<T: ValkeyLockIndicator>(ctx: &T) {
    let settings = VkConnectionSettings::new(
        is_starttls_enabled(ctx),
        get_tls_ca_cert_path(ctx),
        get_tls_cert_path(ctx),
        get_tls_key_path(ctx),
        get_connection_pool_size(ctx),
    );
    vkldap::refresh_connection_settings(settings);
}

pub fn process_server_list(server_list: String) -> Result<(), ValkeyError> {
    if server_list.is_empty() {
        return match vkldap::clear_server_list() {
            Ok(_) => Ok(()),
            Err(err) => {
                error!("clear server list returned an error: {err}");
                Err(ValkeyError::Str(
                    "Failed to set the LDAP servers. Check the logs for more details.",
                ))
            }
        };
    }

    let urls = server_list.split(" ");
    let mut url_list = LinkedList::new();
    for url_str in urls {
        let parse_res = Url::parse(url_str);
        match parse_res {
            Ok(url) => url_list.push_back(url),
            Err(e) => return Err(ValkeyError::String(e.to_string())),
        }
    }

    let res = vkldap::clear_server_list();
    if let Err(err) = res {
        error!("clear server list returned an error: {err}");
        return Err(ValkeyError::Str(
            "Failed to set the LDAP servers. Check the logs for more details.",
        ));
    }

    for url in url_list {
        debug!("adding server URL {url:?}");
        let res = vkldap::add_server(url);
        if let Err(err) = res {
            error!("add server returned an error: {err}");
            return Err(ValkeyError::Str(
                "Failed to set the LDAP servers. Check the logs for more details.",
            ));
        }
    }

    Ok(())
}

pub fn on_password_config_set<G, T: ConfigurationValue<ValkeyString>>(
    ctx: &ConfigurationContext,
    _name: &str,
    val: &'static T,
) -> Result<(), ValkeyError> {
    LDAP_SEARCH_BIND_PASSWD.set(ctx, val.get(ctx))?;

    refresh_ldap_settings_cache(ctx);

    val.set(ctx, ValkeyString::create(None, "*********"))
}

pub fn on_ldap_setting_change<G, T: ConfigurationValue<G>>(
    ctx: &ConfigurationContext,
    _name: &str,
    _val: &'static T,
) {
    refresh_ldap_settings_cache(ctx);
}

pub fn on_connection_setting_change<G, T: ConfigurationValue<G>>(
    ctx: &ConfigurationContext,
    _name: &str,
    _val: &'static T,
) {
    refresh_connection_settings_cache(ctx);
}

pub fn failure_detector_interval_changed<G, T: ConfigurationValue<G>>(
    ctx: &ConfigurationContext,
    _name: &str,
    _val: &'static T,
) {
    failure_detector::set_failure_detector_interval(get_failure_detector_interval_secs(ctx));
}

pub fn ldap_server_list_set_callback(
    config_ctx: &ConfigurationContext,
    _: &str,
    value: &'static ValkeyGILGuard<ValkeyString>,
) -> Result<(), ValkeyError> {
    let val_str = value.get(config_ctx).to_string_lossy();
    process_server_list(val_str)
}

pub fn get_bind_dn_prefix<T: ValkeyLockIndicator>(ctx: &T) -> String {
    let bind_dn_prefix = LDAP_BIND_DN_PREFIX.lock(ctx);
    bind_dn_prefix.to_string_lossy()
}

pub fn get_bind_dn_suffix<T: ValkeyLockIndicator>(ctx: &T) -> String {
    let bind_dn_suffix = LDAP_BIND_DN_SUFFIX.lock(ctx);
    bind_dn_suffix.to_string_lossy()
}

pub fn get_tls_ca_cert_path<T: ValkeyLockIndicator>(ctx: &T) -> Option<String> {
    let tls_ca_cert_path = LDAP_TLS_CA_CERT_PATH.lock(ctx);
    let tls_ca_cert_path_str = tls_ca_cert_path.to_string();
    match tls_ca_cert_path_str.as_str() {
        "" => None,
        _ => Some(tls_ca_cert_path_str),
    }
}

pub fn get_tls_cert_path<T: ValkeyLockIndicator>(ctx: &T) -> Option<String> {
    let tls_cert_path = LDAP_TLS_CERT_PATH.lock(ctx);
    let tls_cert_path_str = tls_cert_path.to_string();
    match tls_cert_path_str.as_str() {
        "" => None,
        _ => Some(tls_cert_path_str),
    }
}

pub fn get_tls_key_path<T: ValkeyLockIndicator>(ctx: &T) -> Option<String> {
    let tls_key_path = LDAP_TLS_KEY_PATH.lock(ctx);
    let tls_key_path_str = tls_key_path.to_string();
    match tls_key_path_str.as_str() {
        "" => None,
        _ => Some(tls_key_path_str),
    }
}

pub fn is_starttls_enabled<T: ValkeyLockIndicator>(ctx: &T) -> bool {
    let use_starttls = LDAP_USE_STARTTLS.lock(ctx);
    *use_starttls
}

pub fn is_auth_enabled<T: ValkeyLockIndicator>(ctx: &T) -> bool {
    let auth_enabled = LDAP_AUTH_ENABLED.lock(ctx);
    *auth_enabled
}

pub fn is_bind_mode<T: ValkeyLockIndicator>(ctx: &T) -> bool {
    let auth_mode = LDAP_AUTH_MODE.lock(ctx);
    *auth_mode == LdapAuthMode::Bind
}

pub fn get_search_base<T: ValkeyLockIndicator>(ctx: &T) -> Option<String> {
    let search_base = LDAP_SEARCH_BASE.lock(ctx);
    let search_base_str = search_base.to_string();
    match search_base_str.as_str() {
        "" => None,
        _ => Some(search_base_str),
    }
}

pub fn get_search_scope<T: ValkeyLockIndicator>(ctx: &T) -> LdapSearchScope {
    let search_scope = LDAP_SEARCH_SCOPE.lock(ctx);
    search_scope.clone()
}

pub fn get_search_filter<T: ValkeyLockIndicator>(ctx: &T) -> Option<String> {
    let search_filter = LDAP_SEARCH_FILTER.lock(ctx);
    let search_filter_str = search_filter.to_string();
    match search_filter_str.as_str() {
        "" => None,
        _ => Some(search_filter_str),
    }
}

pub fn get_search_attribute<T: ValkeyLockIndicator>(ctx: &T) -> Option<String> {
    let search_attribute = LDAP_SEARCH_ATTRIBUTE.lock(ctx);
    let search_attribute_str = search_attribute.to_string();
    match search_attribute_str.as_str() {
        "" => None,
        _ => Some(search_attribute_str),
    }
}

pub fn get_search_bind_dn<T: ValkeyLockIndicator>(ctx: &T) -> Option<String> {
    let bind_dn = LDAP_SEARCH_BIND_DN.lock(ctx);
    let bind_dn_str = bind_dn.to_string();
    match bind_dn_str.as_str() {
        "" => None,
        _ => Some(bind_dn_str),
    }
}

pub fn get_search_bind_passwd<T: ValkeyLockIndicator>(ctx: &T) -> Option<String> {
    let bind_passwd = LDAP_SEARCH_BIND_PASSWD.lock(ctx);
    let bind_passwd_str = bind_passwd.to_string();
    match bind_passwd_str.as_str() {
        "" => None,
        _ => Some(bind_passwd_str),
    }
}

pub fn get_search_dn_attribute<T: ValkeyLockIndicator>(ctx: &T) -> String {
    let dn_attribute = LDAP_SEARCH_DN_ATTRIBUTE.lock(ctx);
    dn_attribute.to_string()
}

pub fn get_connection_pool_size<T: ValkeyLockIndicator>(ctx: &T) -> usize {
    let pool_size = LDAP_CONNECTION_POOL_SIZE.lock(ctx);
    *pool_size as usize
}

pub fn get_failure_detector_interval_secs<T: ValkeyLockIndicator>(ctx: &T) -> u64 {
    let interval = LDAP_FAILURE_DETECTOR_INTERVAL.lock(ctx);
    *interval as u64
}
