use std::collections::LinkedList;

use crate::vkldap::{add_server, clear_server_list};
use log::debug;
use url::Url;

use lazy_static::lazy_static;
use valkey_module::{
    ConfigurationValue, Context, ValkeyError, ValkeyGILGuard, ValkeyString,
    configuration::ConfigurationContext,
};

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
}

pub fn ldap_server_list_set_callback(
    config_ctx: &ConfigurationContext,
    _: &str,
    value: &'static ValkeyGILGuard<ValkeyString>,
) -> Result<(), ValkeyError> {
    let val_str = value.get(config_ctx).to_string_lossy();

    if val_str.is_empty() {
        clear_server_list();
        return Ok(());
    }

    let urls = val_str.split(",");
    let mut url_list = LinkedList::new();
    for url_str in urls {
        let parse_res = Url::parse(url_str);
        match parse_res {
            Ok(url) => url_list.push_back(url),
            Err(e) => return Err(ValkeyError::String(e.to_string())),
        }
    }

    clear_server_list();
    for url in url_list {
        debug!(target: "ldap::configs", "Adding server URL {url:?}");
        add_server(url);
    }

    Ok(())
}

pub fn get_bind_dn_prefix(mod_ctx: &Context) -> String {
    let bind_dn_prefix = LDAP_BIND_DN_PREFIX.lock(mod_ctx);
    bind_dn_prefix.to_string_lossy()
}

pub fn get_bind_dn_suffix(mod_ctx: &Context) -> String {
    let bind_dn_suffix = LDAP_BIND_DN_SUFFIX.lock(mod_ctx);
    bind_dn_suffix.to_string_lossy()
}

pub fn get_tls_ca_cert_path(mod_ctx: &Context) -> Option<String> {
    let tls_ca_cert_path = LDAP_TLS_CA_CERT_PATH.lock(mod_ctx);
    let tls_ca_cert_path_str = tls_ca_cert_path.to_string();
    match tls_ca_cert_path_str.as_str() {
        "" => None,
        _ => Some(tls_ca_cert_path_str),
    }
}

pub fn get_tls_cert_path(mod_ctx: &Context) -> Option<String> {
    let tls_cert_path = LDAP_TLS_CERT_PATH.lock(mod_ctx);
    let tls_cert_path_str = tls_cert_path.to_string();
    match tls_cert_path_str.as_str() {
        "" => None,
        _ => Some(tls_cert_path_str),
    }
}

pub fn get_tls_key_path(mod_ctx: &Context) -> Option<String> {
    let tls_key_path = LDAP_TLS_KEY_PATH.lock(mod_ctx);
    let tls_key_path_str = tls_key_path.to_string();
    match tls_key_path_str.as_str() {
        "" => None,
        _ => Some(tls_key_path_str),
    }
}

pub fn is_starttls_enabled(mod_ctx: &Context) -> bool {
    let use_starttls = LDAP_USE_STARTTLS.lock(mod_ctx);
    *use_starttls
}

pub fn is_auth_enabled(mod_ctx: &Context) -> bool {
    let auth_enabled = LDAP_AUTH_ENABLED.lock(mod_ctx);
    *auth_enabled
}
