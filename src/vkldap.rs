use lazy_static::lazy_static;
use ldap3::{LdapConn, LdapConnSettings, LdapError, Scope, SearchEntry};
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

pub fn from_string_to_scope(scope_str: &str) -> Scope {
    match scope_str {
        "base" => Scope::Base,
        "one" => Scope::OneLevel,
        "sub" => Scope::Subtree,
        _ => Scope::Subtree,
    }
}

pub struct VkLdapSettings {
    use_starttls: bool,
    ca_cert_path: Option<String>,
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
    bind_db_prefix: String,
    bind_db_suffix: String,
    search_base: Option<String>,
    search_scope: Scope,
    search_filter: Option<String>,
    search_attribute: Option<String>,
    search_bind_dn: Option<String>,
    search_bind_passwd: Option<String>,
    search_dn_attribute: String,
}

impl VkLdapSettings {
    pub fn new(
        use_starttls: bool,
        ca_cert_path: Option<String>,
        client_cert_path: Option<String>,
        client_key_path: Option<String>,
        bind_db_prefix: String,
        bind_db_suffix: String,
        search_base: Option<String>,
        search_scope: Scope,
        search_filter: Option<String>,
        search_attribute: Option<String>,
        search_bind_dn: Option<String>,
        search_bind_passwd: Option<String>,
        search_dn_attribute: String,
    ) -> Self {
        Self {
            use_starttls,
            ca_cert_path,
            client_cert_path,
            client_key_path,
            bind_db_prefix,
            bind_db_suffix,
            search_base,
            search_scope,
            search_filter,
            search_attribute,
            search_bind_dn,
            search_bind_passwd,
            search_dn_attribute,
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

    fn bind(&mut self, user_dn: &str, password: &str) -> Result<()> {
        let _ = self.ldap_conn.simple_bind(user_dn, password)?.success()?;
        debug!("LDAP bind successful for user {user_dn}");
        Ok(())
    }

    fn search(&mut self, username: &str) -> Result<String> {
        if let Some(bind_dn) = &self.settings.search_bind_dn {
            if let Some(bind_passwd) = &self.settings.search_bind_passwd {
                let _ = self
                    .ldap_conn
                    .simple_bind(&bind_dn, &bind_passwd)?
                    .success()?;
            }
        }

        let mut base = "";
        if let Some(sbase) = &self.settings.search_base {
            base = &sbase;
        }

        let mut filter = "objectClass=*";
        if let Some(sfilter) = &self.settings.search_filter {
            filter = &sfilter;
        }

        let mut attribute = "uid";
        if let Some(sattribute) = &self.settings.search_attribute {
            attribute = &sattribute;
        }

        let search_filter = format!("(&({filter})({attribute}={username}))");

        debug!("search user entry using the filter '{search_filter}'");

        let (rs, _res) = self
            .ldap_conn
            .search(
                base,
                self.settings.search_scope,
                search_filter.as_str(),
                vec![&self.settings.search_dn_attribute],
            )?
            .success()?;

        if rs.len() == 0 {
            return Err(VkLdapError::String(
                "the LDAP search query did not return any entry".to_string(),
            ));
        }

        if rs.len() > 1 {
            return Err(VkLdapError::String(
                "the LDAP search query did not return a single entry".to_string(),
            ));
        }

        let entry = rs
            .into_iter()
            .next()
            .expect("there should be one element in rs");
        let sentry = SearchEntry::construct(entry);

        Ok(sentry.attrs[&self.settings.search_dn_attribute][0].clone())
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
    let prefix = &ldap_ctx.settings.bind_db_prefix;
    let suffix = &ldap_ctx.settings.bind_db_suffix;
    let user_dn = format!("{prefix}{username}{suffix}");
    ldap_ctx.bind(user_dn.as_str(), password)
}

pub fn vk_ldap_search_and_bind(
    settings: VkLdapSettings,
    username: &str,
    password: &str,
) -> Result<()> {
    let mut ldap_ctx = get_ldap_context(settings)?;
    let user_dn = ldap_ctx.search(username)?;
    ldap_ctx.bind(user_dn.as_str(), password)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
