use lazy_static::lazy_static;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, LdapError, Scope, SearchEntry};
use log::{debug, info, warn};
use native_tls::{Certificate, Identity, TlsConnector};
use std::{
    fs,
    sync::Mutex,
    thread::{self, JoinHandle},
    time::Duration,
};
use url::Url;
use valkey_module::ValkeyError;

use crate::configs::LdapSearchScope;

use futures::future;

use tokio;

#[derive(Clone)]
pub enum VkLdapServerStatus {
    HEALTHY,
    UNHEALTHY(String),
}

impl std::fmt::Display for VkLdapServerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HEALTHY => write!(f, "HEALTHY"),
            Self::UNHEALTHY(msg) => write!(f, "UNHEALTHY: {msg}"),
        }
    }
}

impl PartialEq for VkLdapServerStatus {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

#[derive(Clone)]
pub struct VkLdapServer {
    pub url: Url,
    id: usize,
    pub status: VkLdapServerStatus,
}

async fn check_server_health_async(
    settings: &VkLdapSettings,
    server_id: usize,
    server_url: &Url,
) -> (String, usize, Result<()>) {
    match VkLdapContext::create_ldap_connection(settings, &server_url).await {
        Ok(mut handler) => {
            let _ = handler.unbind().await;
            (server_url.to_string(), server_id, Ok(()))
        }
        Err(err) => (server_url.to_string(), server_id, Err(err)),
    }
}

async fn check_servers_health(
    servers: Vec<VkLdapServer>,
    settings: VkLdapSettings,
) -> Vec<(std::string::String, usize, Result<()>)> {
    let mut futures = Vec::new();

    for server in servers.iter() {
        let check_health_fut = check_server_health_async(&settings, server.id, &server.url);
        futures.push(check_health_fut);
    }

    future::join_all(futures).await
}

struct VkLdapServerInfo {
    url: Url,
    id: usize,
}

struct VkLdapConfig {
    servers: Vec<VkLdapServer>,
    stop_failure_detector: bool,
    detector_thread_handle: Option<thread::JoinHandle<()>>,
    settings: VkLdapSettings,
}

impl VkLdapConfig {
    fn new() -> VkLdapConfig {
        VkLdapConfig {
            servers: Vec::new(),
            stop_failure_detector: false,
            detector_thread_handle: None,
            settings: VkLdapSettings::default(),
        }
    }

    fn get_settings_copy(&self) -> VkLdapSettings {
        self.settings.clone()
    }

    fn refresh_settings(&mut self, settings: VkLdapSettings) {
        self.settings = settings
    }

    fn clear_server_list(&mut self) -> () {
        self.servers.clear();
    }

    fn add_server(&mut self, server_url: Url) -> () {
        self.servers.push(VkLdapServer {
            url: server_url,
            id: self.servers.len(),
            status: VkLdapServerStatus::HEALTHY,
        });
    }

    fn get_current_servers(&self) -> Vec<VkLdapServer> {
        let mut res: Vec<VkLdapServer> = Vec::new();
        self.servers.iter().for_each(|s| res.push(s.clone()));
        res
    }

    fn update_server_status(
        &mut self,
        server_url: String,
        server_id: usize,
        status: VkLdapServerStatus,
    ) {
        if server_id >= self.servers.len() {
            return ();
        }

        let server = &mut self.servers[server_id];
        if server.url.to_string() != server_url {
            return ();
        }

        if server.status != status {
            let pre_status = &server.status;
            info!("transition server {server_url} {pre_status} -> {status}");
            server.status = status;
        }
    }

    fn find_server(&self) -> Result<VkLdapServerInfo> {
        if self.servers.is_empty() {
            return Err(VkLdapError::NoServerConfigured);
        }

        for server in self.servers.iter() {
            if let VkLdapServerStatus::HEALTHY = server.status {
                return Ok(VkLdapServerInfo {
                    url: server.url.clone(),
                    id: server.id,
                });
            }
        }

        Err(VkLdapError::NoHealthyServerAvailable)
    }

    fn failover_server(
        &mut self,
        failed_server: VkLdapServerInfo,
        err: &VkLdapError,
    ) -> Result<VkLdapServerInfo> {
        if self.servers.is_empty() {
            // The server list was cleared in the meantime, no new server can be returned.
            return Err(VkLdapError::NoServerConfigured);
        }
        let next_server_index = (failed_server.id + 1) % self.servers.len();

        if let VkLdapServerStatus::HEALTHY = self.servers[failed_server.id].status {
            if self.servers[failed_server.id].url == failed_server.url {
                // Mark the server unhealthy with the last error raised by the LDAP connection.
                let url = &failed_server.url;
                let err_msg = err.to_string();
                info!("transition server {url} HEALTHY -> UNHEALTHY: {err_msg}");
                self.servers[failed_server.id].status = VkLdapServerStatus::UNHEALTHY(err_msg);
            }
        }

        for idx in next_server_index..self.servers.len() {
            let new_server = &self.servers[idx];
            if let VkLdapServerStatus::HEALTHY = new_server.status {
                return Ok(VkLdapServerInfo {
                    url: new_server.url.clone(),
                    id: new_server.id,
                });
            }
        }

        Err(VkLdapError::NoHealthyServerAvailable)
    }
}

lazy_static! {
    static ref LDAP_CONFIG: Mutex<VkLdapConfig> = Mutex::new(VkLdapConfig::new());
}

pub enum VkLdapError {
    IOError(String, std::io::Error),
    NoTLSKeyPathSet,
    TLSError(String, native_tls::Error),
    LdapBindError(LdapError),
    LdapAdminBindError(LdapError),
    LdapSearchError(LdapError),
    LdapConnectionError(LdapError),
    NoLdapEntryFound(String),
    MultipleEntryFound(String),
    NoServerConfigured,
    NoHealthyServerAvailable,
    FailedToStopFailuredDetectorThread,
}

impl std::fmt::Display for VkLdapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VkLdapError::NoTLSKeyPathSet => write!(
                f,
                "no TLS key path specified. Please set the path for ldap.tls_key_path config"
            ),
            VkLdapError::IOError(msg, ioerr) => write!(f, "{msg}: {ioerr}"),
            VkLdapError::TLSError(msg, tlserr) => write!(f, "{msg}: {tlserr}"),
            VkLdapError::LdapBindError(ldaperr) => {
                write!(f, "error in bind operation: {ldaperr}")
            }
            VkLdapError::LdapAdminBindError(ldaperr) => {
                write!(f, "error in binding admin user: {ldaperr}")
            }
            VkLdapError::LdapSearchError(ldaperr) => {
                write!(f, "failed to search ldap user: {ldaperr}")
            }
            VkLdapError::LdapConnectionError(ldaperr) => {
                write!(f, "failed to establish an LDAP connection: {ldaperr}")
            }
            VkLdapError::NoLdapEntryFound(filter) => {
                write!(f, "search filter '{filter}' returned no entries")
            }
            VkLdapError::MultipleEntryFound(filter) => {
                write!(f, "search filter '{filter}' returned multiple entries")
            }
            VkLdapError::NoServerConfigured => write!(
                f,
                "no server set in configuration. Please set ldap.servers config option"
            ),
            VkLdapError::NoHealthyServerAvailable => write!(
                f,
                "all servers set in configuration are unhealthy. Please check the logs for more information"
            ),
            VkLdapError::FailedToStopFailuredDetectorThread => write!(
                f,
                "failed to wait for the failure detector thread to finish"
            ),
        }
    }
}

impl From<&VkLdapError> for ValkeyError {
    fn from(err: &VkLdapError) -> Self {
        err.into()
    }
}

macro_rules! handle_io_error {
    ($expr:expr, $errmsg:expr) => {
        match $expr {
            Ok(res) => res,
            Err(err) => return Err(VkLdapError::IOError($errmsg, err)),
        }
    };
}

macro_rules! handle_tls_error {
    ($expr:expr, $errmsg:expr) => {
        match $expr {
            Ok(res) => res,
            Err(err) => return Err(VkLdapError::TLSError($errmsg, err)),
        }
    };
}

macro_rules! handle_ldap_error {
    ($expr:expr, $errtype:expr) => {
        match $expr {
            Ok(res) => match res.success() {
                Ok(res) => res,
                Err(err) => return Err($errtype(err)),
            },
            Err(err) => return Err($errtype(err)),
        }
    };
}

type Result<T> = std::result::Result<T, VkLdapError>;

impl From<LdapSearchScope> for Scope {
    fn from(value: LdapSearchScope) -> Self {
        match value {
            LdapSearchScope::Base => Scope::Base,
            LdapSearchScope::OneLevel => Scope::OneLevel,
            LdapSearchScope::SubTree => Scope::Subtree,
        }
    }
}

#[derive(Clone)]
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

impl Default for VkLdapSettings {
    fn default() -> Self {
        Self {
            use_starttls: Default::default(),
            ca_cert_path: Default::default(),
            client_cert_path: Default::default(),
            client_key_path: Default::default(),
            bind_db_prefix: Default::default(),
            bind_db_suffix: Default::default(),
            search_base: Default::default(),
            search_scope: Scope::Subtree,
            search_filter: Default::default(),
            search_attribute: Default::default(),
            search_bind_dn: Default::default(),
            search_bind_passwd: Default::default(),
            search_dn_attribute: Default::default(),
        }
    }
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
        search_scope: LdapSearchScope,
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
            search_scope: search_scope.into(),
            search_filter,
            search_attribute,
            search_bind_dn,
            search_bind_passwd,
            search_dn_attribute,
        }
    }
}

struct VkLdapContext {
    ldap_handler: Ldap,
    settings: VkLdapSettings,
}

impl VkLdapContext {
    async fn create_ldap_connection(settings: &VkLdapSettings, server_url: &Url) -> Result<Ldap> {
        let mut ldap_conn_settings = LdapConnSettings::new();

        let use_starttls = settings.use_starttls;
        let requires_tls = server_url.scheme() == "ldaps" || use_starttls;

        if requires_tls {
            let mut tls_builder = &mut TlsConnector::builder();

            if let Some(path) = &settings.ca_cert_path {
                let ca_cert_bytes =
                    handle_io_error!(fs::read(path), "failed to read CA cert file".to_string());
                let ca_cert = handle_tls_error!(
                    Certificate::from_pem(&ca_cert_bytes),
                    "failed to load CA certificate".to_string()
                );
                tls_builder = tls_builder.add_root_certificate(ca_cert);
            }

            if let Some(cert_path) = &settings.client_cert_path {
                match &settings.client_key_path {
                    None => return Err(VkLdapError::NoTLSKeyPathSet),
                    Some(key_path) => {
                        let cert_bytes = handle_io_error!(
                            fs::read(cert_path),
                            "failed to read client certificate file".to_string()
                        );
                        let key_bytes = handle_io_error!(
                            fs::read(key_path),
                            "failed to read client key file".to_string()
                        );
                        let client_cert = handle_tls_error!(
                            Identity::from_pkcs8(&cert_bytes, &key_bytes),
                            "failed to load client certificate".to_string()
                        );
                        tls_builder = tls_builder.identity(client_cert);
                    }
                }
            }

            let tls_connector = handle_tls_error!(
                tls_builder.build(),
                "failed to setup TLS connection".to_string()
            );

            ldap_conn_settings = ldap_conn_settings.set_connector(tls_connector);
            ldap_conn_settings = ldap_conn_settings.set_starttls(settings.use_starttls);
        }

        match LdapConnAsync::from_url_with_settings(ldap_conn_settings, &server_url).await {
            Ok((conn, handler)) => {
                ldap3::drive!(conn);
                Ok(handler)
            }
            Err(err) => Err(VkLdapError::LdapConnectionError(err)),
        }
    }

    async fn new(settings: VkLdapSettings) -> Result<Self> {
        let mut server: VkLdapServerInfo;
        {
            let config = LDAP_CONFIG.lock().unwrap();
            server = config.find_server()?;
        }

        loop {
            let url = &server.url;
            debug!("creating LDAP connection to {url}");
            match Self::create_ldap_connection(&settings, &server.url).await {
                Ok(ldap_handler) => {
                    return Ok(VkLdapContext {
                        ldap_handler,
                        settings,
                    });
                }
                Err(err) => match err {
                    VkLdapError::LdapConnectionError(_) => {
                        let mut config = LDAP_CONFIG.lock().unwrap();
                        let failover_server = config.failover_server(server, &err);

                        match failover_server {
                            Ok(new_server) => {
                                let url = &new_server.url;
                                warn!("failing over to server {url}");
                                server = new_server;
                            }
                            Err(err) => {
                                return Err(err);
                            }
                        };
                    }
                    _ => {
                        return Err(err);
                    }
                },
            }
        }
    }

    async fn bind(&mut self, user_dn: &str, password: &str) -> Result<()> {
        handle_ldap_error!(
            self.ldap_handler.simple_bind(user_dn, password).await,
            VkLdapError::LdapBindError
        );
        Ok(())
    }

    async fn search(&mut self, username: &str) -> Result<String> {
        if let Some(bind_dn) = &self.settings.search_bind_dn {
            if let Some(bind_passwd) = &self.settings.search_bind_passwd {
                handle_ldap_error!(
                    self.ldap_handler.simple_bind(&bind_dn, &bind_passwd).await,
                    VkLdapError::LdapAdminBindError
                );
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

        let (rs, _res) = handle_ldap_error!(
            self.ldap_handler
                .search(
                    base,
                    self.settings.search_scope,
                    search_filter.as_str(),
                    vec![&self.settings.search_dn_attribute],
                )
                .await,
            VkLdapError::LdapSearchError
        );

        if rs.len() == 0 {
            return Err(VkLdapError::NoLdapEntryFound(search_filter));
        }

        if rs.len() > 1 {
            return Err(VkLdapError::MultipleEntryFound(search_filter));
        }

        let entry = rs
            .into_iter()
            .next()
            .expect("there should be one element in rs");
        let sentry = SearchEntry::construct(entry);

        Ok(sentry.attrs[&self.settings.search_dn_attribute][0].clone())
    }

    async fn close(&mut self) {
        let _ = self.ldap_handler.unbind().await;
    }
}

/// PUBLIC Interface

pub fn refresh_settings(settings: VkLdapSettings) {
    LDAP_CONFIG.lock().unwrap().refresh_settings(settings);
}

pub fn clear_server_list() -> () {
    LDAP_CONFIG.lock().unwrap().clear_server_list();
}

pub fn add_server(server_url: Url) {
    LDAP_CONFIG.lock().unwrap().add_server(server_url);
}

#[tokio::main]
pub async fn vk_ldap_bind(username: &str, password: &str) -> Result<()> {
    let settings = LDAP_CONFIG.lock().unwrap().get_settings_copy();
    let mut ldap_ctx = VkLdapContext::new(settings).await?;
    let prefix = &ldap_ctx.settings.bind_db_prefix;
    let suffix = &ldap_ctx.settings.bind_db_suffix;
    let user_dn = format!("{prefix}{username}{suffix}");
    let bind_res = ldap_ctx.bind(user_dn.as_str(), password).await;
    ldap_ctx.close().await;
    bind_res
}

#[tokio::main]
pub async fn vk_ldap_search_and_bind(username: &str, password: &str) -> Result<()> {
    let settings = LDAP_CONFIG.lock().unwrap().get_settings_copy();
    let mut ldap_ctx = VkLdapContext::new(settings).await?;
    let user_dn = ldap_ctx.search(username).await?;
    let bind_res = ldap_ctx.bind(user_dn.as_str(), password).await;
    ldap_ctx.close().await;
    bind_res
}

pub fn stop_ldap_failure_detector() -> Result<()> {
    let handler_opt: Option<JoinHandle<()>>;
    {
        let mut config = LDAP_CONFIG.lock().unwrap();
        config.stop_failure_detector = true;
        handler_opt = config.detector_thread_handle.take();
    }

    if let Some(handler) = handler_opt {
        match handler.join() {
            Ok(_) => Ok(()),
            Err(_) => Err(VkLdapError::FailedToStopFailuredDetectorThread),
        }
    } else {
        panic!("failure detector thread should have been initialized");
    }
}

#[tokio::main]
pub async fn failure_detector_loop() -> () {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let settings;
        {
            settings = LDAP_CONFIG.lock().unwrap().get_settings_copy();
        }

        let servers;
        {
            servers = LDAP_CONFIG.lock().unwrap().get_current_servers();
        }

        let status_res = check_servers_health(servers, settings).await;
        {
            let mut config = LDAP_CONFIG.lock().unwrap();
            for (url, id, res) in status_res {
                match res {
                    Ok(_) => config.update_server_status(url, id, VkLdapServerStatus::HEALTHY),
                    Err(err) => {
                        let err_msg = err.to_string();
                        config.update_server_status(
                            url,
                            id,
                            VkLdapServerStatus::UNHEALTHY(err_msg),
                        );
                    }
                }
            }
        }

        if LDAP_CONFIG.lock().unwrap().stop_failure_detector {
            debug!("exiting failure detector loop");
            return ();
        }
    }
}

pub fn start_ldap_failure_detector() -> () {
    let mut config = LDAP_CONFIG.lock().unwrap();

    config.detector_thread_handle = Some(thread::spawn(|| {
        debug!("initiating failure detector thread");
        failure_detector_loop();
        debug!("shutting down failure detector thread");
    }));
}

pub fn get_servers_health_status() -> Vec<VkLdapServer> {
    LDAP_CONFIG.lock().unwrap().get_current_servers()
}
