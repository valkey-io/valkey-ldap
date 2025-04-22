use crate::configs;
use lazy_static::lazy_static;
use ldap3::{LdapConn, LdapConnSettings, LdapError};
use native_tls::{Certificate, Identity, TlsConnector};
use std::{collections::LinkedList, fs, io, sync::Mutex};
use url::Url;
use valkey_module::{Context as VkModContext, ValkeyError};

struct VkLdapConfig {
    servers: LinkedList<Url>,
}

impl VkLdapConfig {
    fn new() -> VkLdapConfig {
        VkLdapConfig {
            servers: LinkedList::new(),
        }
    }

    fn clear_server_list(&mut self) -> () {
        self.servers.clear();
    }

    fn add_server(&mut self, server_url: Url) -> () {
        self.servers.push_back(server_url);
    }

    pub fn find_server(&self) -> Option<&Url> {
        self.servers.front()
    }
}

lazy_static! {
    static ref LDAP_CONFIG: Mutex<VkLdapConfig> = Mutex::new(VkLdapConfig::new());
}

pub fn clear_server_list() -> () {
    LDAP_CONFIG.lock().unwrap().clear_server_list();
}

pub fn add_server(server_url: Url) {
    LDAP_CONFIG.lock().unwrap().add_server(server_url);
}

pub enum VkLdapError {
    String(String),
}

impl From<LdapError> for VkLdapError {
    fn from(err: LdapError) -> Self {
        VkLdapError::String(format!("hello {err}").to_string())
    }
}

impl From<VkLdapError> for ValkeyError {
    fn from(err: VkLdapError) -> Self {
        let VkLdapError::String(msg) = err;
        ValkeyError::String(msg)
    }
}

impl From<io::Error> for VkLdapError {
    fn from(err: std::io::Error) -> Self {
        VkLdapError::String(format!("LDAP error: {err}").to_string())
    }
}

impl From<native_tls::Error> for VkLdapError {
    fn from(err: native_tls::Error) -> Self {
        VkLdapError::String(format!("LDAP error: {err}").to_string())
    }
}

type Result<T> = std::result::Result<T, VkLdapError>;

struct VkLdapContext<'a> {
    mod_ctx: &'a VkModContext,
    ldap_conn: LdapConn,
}

impl<'a> VkLdapContext<'a> {
    fn new<'b: 'a>(ctx: &'b VkModContext, url: &Url) -> Result<Self> {
        let mut ldap_conn_settings = LdapConnSettings::new();

        let use_starttls = configs::is_starttls_enabled(ctx);
        let requires_tls = url.scheme() == "ldaps" || use_starttls;

        if requires_tls {
            let mut tls_builder = &mut TlsConnector::builder();

            if let Some(path) = configs::get_tls_ca_cert_path(ctx) {
                let ca_cert_bytes = fs::read(path.as_str())?;
                let ca_cert = Certificate::from_pem(&ca_cert_bytes)?;
                tls_builder = tls_builder.add_root_certificate(ca_cert);
            }

            if let Some(cert_path) = configs::get_tls_cert_path(ctx) {
                match configs::get_tls_key_path(ctx) {
                    None => return Err(VkLdapError::String("LDAP error: no TLS key path specified. Please set the path for ldap.tls_key_path config".to_string())),
                    Some(key_path) => {
                        let cert_bytes = fs::read(cert_path.as_str())?;
                        let key_bytes = fs::read(key_path.as_str())?;
                        let client_cert = Identity::from_pkcs8(&cert_bytes, &key_bytes)?;
                        tls_builder = tls_builder.identity(client_cert);
                    }
                }
            }

            let tls_connector = tls_builder.build()?;

            ldap_conn_settings = ldap_conn_settings.set_connector(tls_connector);
            ldap_conn_settings = ldap_conn_settings.set_starttls(use_starttls);
        }

        Ok(VkLdapContext {
            mod_ctx: ctx,
            ldap_conn: LdapConn::with_settings(ldap_conn_settings, url.as_str())?,
        })
    }

    fn bind(&mut self, user: &str, pass: &str) -> Result<()> {
        let prefix = configs::get_bind_dn_prefix(self.mod_ctx);
        let suffix = configs::get_bind_dn_suffix(self.mod_ctx);
        let _ = self
            .ldap_conn
            .simple_bind(format!("{prefix}{user}{suffix}").as_str(), pass)?
            .success()?;
        self.mod_ctx.log_debug("LDAP bind successful");
        Ok(())
    }
}

impl Drop for VkLdapContext<'_> {
    fn drop(&mut self) {
        match self.ldap_conn.unbind() {
            Ok(_) => (),
            Err(_) => (),
        }
        self.mod_ctx.log_debug("LDAP connection dropped");
    }
}

fn get_ldap_context(mod_ctx: &VkModContext) -> Result<VkLdapContext> {
    let config = LDAP_CONFIG.lock().unwrap();
    let url_opt = config.find_server();
    match url_opt {
        Some(url) => VkLdapContext::new(mod_ctx, &url),
        None => Err(VkLdapError::String(
            "ERR no server set in configuration. Please set ldap.servers config.".to_string(),
        )),
    }
}

pub fn vk_ldap_bind(mod_ctx: &VkModContext, user: &str, pass: &str) -> Result<()> {
    let mut ldap_ctx = get_ldap_context(mod_ctx)?;
    ldap_ctx.bind(user, pass)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
