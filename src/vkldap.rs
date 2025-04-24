use lazy_static::lazy_static;
use ldap3::{LdapConn, LdapConnSettings, LdapError};
use log::debug;
use native_tls::{Certificate, Identity, TlsConnector};
use std::{collections::LinkedList, fs, io, sync::Mutex};
use url::Url;
use valkey_module::ValkeyError;

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

impl Clone for VkLdapError {
    fn clone(&self) -> Self {
        match self {
            Self::String(msg) => Self::String(msg.clone()),
        }
    }
}

impl std::fmt::Display for VkLdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let VkLdapError::String(msg) = self;
        write!(f, "{}", msg)
    }
}

impl From<LdapError> for VkLdapError {
    fn from(err: LdapError) -> Self {
        VkLdapError::String(format!("LDAP error: {err}").to_string())
    }
}

impl From<VkLdapError> for ValkeyError {
    fn from(err: VkLdapError) -> Self {
        let VkLdapError::String(msg) = err;
        ValkeyError::String(msg)
    }
}

impl From<&VkLdapError> for ValkeyError {
    fn from(err: &VkLdapError) -> Self {
        let VkLdapError::String(msg) = err;
        ValkeyError::String(msg.clone())
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

pub struct VkLdapSettings {
    use_starttls: bool,
    ca_cert_path: Option<String>,
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
    bind_db_prefix: String,
    bind_db_suffix: String,
}

impl VkLdapSettings {
    pub fn new(
        use_starttls: bool,
        ca_cert_path: Option<String>,
        client_cert_path: Option<String>,
        client_key_path: Option<String>,
        bind_db_prefix: String,
        bind_db_suffix: String,
    ) -> Self {
        Self {
            use_starttls: use_starttls,
            ca_cert_path: ca_cert_path,
            client_cert_path: client_cert_path,
            client_key_path: client_key_path,
            bind_db_prefix: bind_db_prefix,
            bind_db_suffix: bind_db_suffix,
        }
    }
}

struct VkLdapContext {
    ldap_conn: LdapConn,
    settings: VkLdapSettings,
}

impl VkLdapContext {
    fn new(settings: VkLdapSettings, url: &Url) -> Result<Self> {
        let mut ldap_conn_settings = LdapConnSettings::new();

        let use_starttls = settings.use_starttls;
        let requires_tls = url.scheme() == "ldaps" || use_starttls;

        if requires_tls {
            let mut tls_builder = &mut TlsConnector::builder();

            if let Some(path) = &settings.ca_cert_path {
                let ca_cert_bytes = fs::read(path)?;
                let ca_cert = Certificate::from_pem(&ca_cert_bytes)?;
                tls_builder = tls_builder.add_root_certificate(ca_cert);
            }

            if let Some(cert_path) = &settings.client_cert_path {
                match &settings.client_key_path {
                    None => return Err(VkLdapError::String("LDAP error: no TLS key path specified. Please set the path for ldap.tls_key_path config".to_string())),
                    Some(key_path) => {
                        let cert_bytes = fs::read(cert_path)?;
                        let key_bytes = fs::read(key_path)?;
                        let client_cert = Identity::from_pkcs8(&cert_bytes, &key_bytes)?;
                        tls_builder = tls_builder.identity(client_cert);
                    }
                }
            }

            let tls_connector = tls_builder.build()?;

            ldap_conn_settings = ldap_conn_settings.set_connector(tls_connector);
            ldap_conn_settings = ldap_conn_settings.set_starttls(settings.use_starttls);
        }

        Ok(VkLdapContext {
            ldap_conn: LdapConn::with_settings(ldap_conn_settings, url.as_str())?,
            settings: settings,
        })
    }

    fn bind(&mut self, username: &str, password: &str) -> Result<()> {
        let prefix = &self.settings.bind_db_prefix;
        let suffix = &self.settings.bind_db_suffix;
        let _ = self
            .ldap_conn
            .simple_bind(format!("{prefix}{username}{suffix}").as_str(), password)?
            .success()?;
        debug!("LDAP bind successful for user {username}");
        Ok(())
    }
}

impl Drop for VkLdapContext {
    fn drop(&mut self) {
        match self.ldap_conn.unbind() {
            Ok(_) => (),
            Err(_) => (),
        }
    }
}

fn get_ldap_context(settings: VkLdapSettings) -> Result<VkLdapContext> {
    let config = LDAP_CONFIG.lock().unwrap();
    let url_opt = config.find_server();
    match url_opt {
        Some(url) => VkLdapContext::new(settings, url),
        None => Err(VkLdapError::String(
            "ERR no server set in configuration. Please set ldap.servers config.".to_string(),
        )),
    }
}

pub fn vk_ldap_bind(settings: VkLdapSettings, username: &str, password: &str) -> Result<()> {
    let mut ldap_ctx = get_ldap_context(settings)?;
    ldap_ctx.bind(username, password)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
